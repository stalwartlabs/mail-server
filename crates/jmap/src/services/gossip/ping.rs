/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    core::BuildServer,
    ipc::{HousekeeperEvent, QueueEvent},
};
use trc::ClusterEvent;

use crate::services::index::Indexer;

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
        let server = self.inner.build_server();

        tokio::spawn(async move {
            trc::event!(Cluster(ClusterEvent::OneOrMorePeersOffline));

            server.request_fts_index();
            let _ = server.inner.ipc.queue_tx.send(QueueEvent::Reload).await;
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
            trc::event!(Cluster(ClusterEvent::EmptyPacket));

            return;
        }

        let mut remove_seeds = false;
        let mut update_config = false;
        let mut update_lists = false;
        let mut update_permissions = false;

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
                                    trc::event!(
                                        Cluster(ClusterEvent::PeerHasChanges),
                                        RemoteIp = peer.addr,
                                        Details = "settings"
                                    );

                                    update_config = true;
                                }
                            }
                            if local_peer.gen_lists != peer.gen_lists {
                                local_peer.gen_lists = peer.gen_lists;
                                if local_peer.hb_sum > 0 {
                                    trc::event!(
                                        Cluster(ClusterEvent::PeerHasChanges),
                                        RemoteIp = peer.addr,
                                        Details = "blocked_ips"
                                    );

                                    update_lists = true;
                                }
                            }
                            if local_peer.gen_permissions != peer.gen_permissions {
                                local_peer.gen_permissions = peer.gen_permissions;
                                if local_peer.hb_sum > 0 {
                                    trc::event!(
                                        Cluster(ClusterEvent::PeerHasChanges),
                                        RemoteIp = peer.addr,
                                        Details = "permissions"
                                    );

                                    update_permissions = true;
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
            trc::event!(Cluster(ClusterEvent::PeerDiscovered), RemoteIp = peer.addr);
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
        if update_permissions {
            self.inner.data.permissions.clear();
        }

        if update_config || update_lists {
            let server = self.inner.build_server();

            tokio::spawn(async move {
                let result = if update_config {
                    server.reload().await
                } else {
                    server.reload_blocked_ips().await
                };
                match result {
                    Ok(result) => {
                        if let Some(new_core) = result.new_core {
                            // Update core
                            server.inner.shared_core.store(new_core.into());

                            // Reload ACME
                            if server
                                .inner
                                .ipc
                                .housekeeper_tx
                                .send(HousekeeperEvent::ReloadSettings)
                                .await
                                .is_err()
                            {
                                trc::event!(
                                    Server(trc::ServerEvent::ThreadError),
                                    Details = "Failed to send setting reload event to housekeeper",
                                    CausedBy = trc::location!(),
                                );
                            }
                        }
                    }
                    Err(err) => {
                        trc::error!(err
                            .details("Failed to reload settings")
                            .caused_by(trc::location!()));
                    }
                }
            });
        }
    }
}
