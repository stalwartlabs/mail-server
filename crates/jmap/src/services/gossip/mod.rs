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

pub mod heartbeat;
pub mod leave;
pub mod peer;
pub mod ping;
pub mod request;
pub mod spawn;

use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::Instant,
};
use tokio::sync::mpsc;

use crate::JmapInstance;

use self::request::Request;

const UDP_MAX_PAYLOAD: usize = 65500;
const HEARTBEAT_WINDOW: usize = 1 << 10;
const HEARTBEAT_WINDOW_MASK: usize = HEARTBEAT_WINDOW - 1;

pub type EpochId = u64;
pub type GenerationId = u8;

pub struct Gossiper {
    // Local node peer and shard id
    pub addr: IpAddr,
    pub port: u16,

    // Gossip state
    pub epoch: EpochId,

    // Peer list
    pub peers: Vec<Peer>,
    pub last_peer_pinged: usize,

    // IPC
    pub core: JmapInstance,
    pub gossip_tx: mpsc::Sender<(SocketAddr, Request)>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Seed,
    Alive,
    Suspected,
    Offline,
    Left,
}

#[derive(Debug)]
pub struct Peer {
    // Peer identity
    pub addr: IpAddr,

    // Peer status
    pub epoch: EpochId,
    pub gen_config: GenerationId,
    pub gen_lists: GenerationId,
    pub state: State,

    // Heartbeat state
    pub last_heartbeat: Instant,
    pub hb_window: Vec<u32>,
    pub hb_window_pos: usize,
    pub hb_sum: u64,
    pub hb_sq_sum: u64,
    pub hb_is_full: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerStatus {
    pub addr: IpAddr,
    pub epoch: EpochId,
    pub gen_config: GenerationId,
    pub gen_lists: GenerationId,
}

impl From<&Peer> for PeerStatus {
    fn from(peer: &Peer) -> Self {
        PeerStatus {
            addr: peer.addr,
            epoch: peer.epoch,
            gen_config: peer.gen_config,
            gen_lists: peer.gen_lists,
        }
    }
}

impl From<&Gossiper> for PeerStatus {
    fn from(cluster: &Gossiper) -> Self {
        PeerStatus {
            addr: cluster.addr,
            epoch: cluster.epoch,
            gen_config: cluster
                .core
                .jmap_inner
                .config_version
                .load(Ordering::Relaxed),
            gen_lists: cluster
                .core
                .core
                .load()
                .network
                .blocked_ips
                .version
                .load(Ordering::Relaxed),
        }
    }
}

impl Gossiper {
    pub async fn send_gossip(&self, dest: IpAddr, request: Request) {
        if let Err(err) = self
            .gossip_tx
            .send((SocketAddr::new(dest, self.port), request))
            .await
        {
            tracing::error!("Failed to send gossip message: {}", err);
        };
    }
}
