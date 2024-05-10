/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
