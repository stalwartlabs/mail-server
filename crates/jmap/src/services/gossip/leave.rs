/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::services::gossip::State;

use super::request::Request;
use super::{Gossiper, PeerStatus};

impl Gossiper {
    pub async fn broadcast_leave(&self) {
        let mut status: Vec<PeerStatus> = Vec::with_capacity(self.peers.len() + 1);
        status.push(self.into());
        for peer in &self.peers {
            if !peer.is_offline() {
                self.send_gossip(peer.addr, Request::Leave(status.clone()))
                    .await;
            }
        }
    }

    pub async fn handle_leave(&mut self, peers: Vec<PeerStatus>) {
        if let Some(peer) = peers.first() {
            for local_peer in self.peers.iter_mut() {
                if local_peer.addr == peer.addr {
                    tracing::debug!("Peer {} is leaving the cluster.", local_peer.addr);

                    local_peer.state = State::Left;
                    local_peer.epoch = peer.epoch;

                    // Reload
                    self.request_reload();

                    break;
                }
            }
        }
    }
}
