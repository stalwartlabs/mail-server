/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smtp::queue;

use crate::services::housekeeper;

use super::{request::Request, Gossiper, PeerStatus};

impl Gossiper {
    pub async fn ping_peers(&mut self) {
        // Total and alive peers in the cluster.
        let total_peers = self.peers.len();
        let mut alive_peers: u32 = 0;
        let mut node_became_offline = false;

        // Count alive peers
        for peer in self.peers.iter_mut() {
            if !peer.is_offline() {
                if peer.check_heartbeat() {
                    alive_peers += 1;
                } else if peer.hb_sum > 0 {
                    // Node is suspected to be offline
                    node_became_offline = true;
                }
            }
        }

        // Find next peer to ping
        for _ in 0..total_peers {
            self.last_peer_pinged = (self.last_peer_pinged + 1) % total_peers;
            let (peer_state, target_addr) = {
                let peer = &self.peers[self.last_peer_pinged];
                (peer.state, peer.addr)
            };

            match peer_state {
                super::State::Seed => {
                    self.send_gossip(target_addr, Request::Ping(vec![(&*self).into()]))
                        .await;
                    break;
                }
                super::State::Alive | super::State::Suspected => {
                    self.epoch += 1;
                    self.send_gossip(target_addr, Request::Ping(self.build_peer_status()))
                        .await;
                    break;
                }
                super::State::Offline if alive_peers == 0 => {
                    // Probe offline nodes
                    self.send_gossip(target_addr, Request::Ping(self.build_peer_status()))
                        .await;
                    break;
                }
                _ => (),
            }
        }

        if node_became_offline {
            self.request_reload();
        }
    }

    pub fn request_reload(&self) {
        let core = self.core.clone();

        tokio::spawn(async move {
            tracing::debug!("One or more nodes became offline, reloading queues.");

            let _ = core
                .jmap_inner
                .housekeeper_tx
                .send(housekeeper::Event::IndexStart)
                .await;
            let _ = core.smtp_inner.queue_tx.send(queue::Event::Reload).await;
        });
    }

    pub async fn broadcast_ping(&self) {
        let status = self.build_peer_status();
        for peer in &self.peers {
            if !peer.is_offline() {
                self.send_gossip(peer.addr, Request::Pong(status.clone()))
                    .await;
            }
        }
    }

    pub async fn handle_ping(&mut self, peers: Vec<PeerStatus>, send_pong: bool) {
        // Increase epoch
        self.epoch += 1;

        if peers.is_empty() {
            tracing::debug!("Received empty ping packet.");
            return;
        }

        let mut remove_seeds = false;
        let mut update_config = false;
        let mut update_lists = false;

        'outer: for (pos, peer) in peers.into_iter().enumerate() {
            if peer.addr == self.addr {
                continue;
            }

            for local_peer in self.peers.iter_mut() {
                if !local_peer.is_seed() {
                    if local_peer.addr == peer.addr {
                        if peer.epoch > local_peer.epoch || pos == 0 {
                            local_peer.update_heartbeat(pos == 0);
                            local_peer.epoch = peer.epoch;
                            local_peer.addr = peer.addr;
                            if local_peer.gen_config != peer.gen_config {
                                local_peer.gen_config = peer.gen_config;
                                if local_peer.hb_sum > 0 {
                                    tracing::debug!(
                                        "Peer {} has configuration changes.",
                                        peer.addr
                                    );
                                    update_config = true;
                                }
                            }
                            if local_peer.gen_lists != peer.gen_lists {
                                local_peer.gen_lists = peer.gen_lists;
                                if local_peer.hb_sum > 0 {
                                    tracing::debug!("Peer {} has list changes.", peer.addr);
                                    update_lists = true;
                                }
                            }
                        }

                        continue 'outer;
                    }
                } else if !remove_seeds {
                    remove_seeds = true;
                }
            }

            // Add new peer to the list.
            tracing::info!("Discovered new peer at {}.", peer.addr);
            self.peers.push(peer.into());
        }

        if remove_seeds {
            self.peers.retain(|peer| !peer.is_seed());
        }

        if send_pong {
            self.send_gossip(self.peers[0].addr, Request::Pong(self.build_peer_status()))
                .await;
        }

        // Reload settings
        if update_config || update_lists {
            let core = self.core.core.clone();
            let inner = self.core.jmap_inner.clone();

            tokio::spawn(async move {
                let result = if update_config {
                    core.load().reload().await
                } else {
                    core.load().reload_blocked_ips().await
                };
                match result {
                    Ok(result) => {
                        if let Some(new_core) = result.new_core {
                            // Update core
                            core.store(new_core.into());

                            // Reload ACME
                            if let Err(err) = inner
                                .housekeeper_tx
                                .send(housekeeper::Event::AcmeReload)
                                .await
                            {
                                tracing::warn!(
                                    "Failed to send ACME reload event to housekeeper: {}",
                                    err
                                );
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!("Failed to reload configuration: {}", err);
                    }
                }
            });
        }
    }
}
