/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, net::IpAddr, time::Instant};

use super::{Gossiper, Peer, PeerStatus, State, HEARTBEAT_WINDOW};

impl Peer {
    pub fn new_seed(addr: IpAddr) -> Self {
        Peer {
            epoch: 0,
            gen_config: 0,
            gen_lists: 0,
            addr,
            state: State::Seed,
            last_heartbeat: Instant::now(),
            hb_window: vec![0; HEARTBEAT_WINDOW],
            hb_window_pos: 0,
            hb_sum: 0,
            hb_sq_sum: 0,
            hb_is_full: false,
        }
    }

    pub fn is_seed(&self) -> bool {
        self.state == State::Seed
    }

    pub fn is_alive(&self) -> bool {
        self.state == State::Alive
    }

    pub fn is_suspected(&self) -> bool {
        self.state == State::Suspected
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.state, State::Alive | State::Suspected)
    }

    pub fn is_offline(&self) -> bool {
        matches!(self.state, State::Offline | State::Left)
    }
}

impl Gossiper {
    pub fn is_peer_healthy(&self, addr: &IpAddr) -> bool {
        self.peers.iter().any(|p| &p.addr == addr && p.is_healthy())
    }

    pub fn get_peer(&self, addr: &IpAddr) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.addr == addr)
    }

    pub fn is_known_peer(&self, addr: &IpAddr) -> bool {
        self.peers.iter().any(|p| &p.addr == addr)
    }

    pub fn get_peer_mut(&mut self, addr: &IpAddr) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| &p.addr == addr)
    }

    pub fn build_peer_status(&self) -> Vec<PeerStatus> {
        let mut result: Vec<PeerStatus> = Vec::with_capacity(self.peers.len() + 1);
        result.push(self.into());
        for peer in self.peers.iter() {
            result.push(peer.into());
        }
        result
    }
}

impl From<PeerStatus> for Peer {
    fn from(value: PeerStatus) -> Self {
        Peer {
            addr: value.addr,
            epoch: value.epoch,
            gen_config: value.gen_config,
            gen_lists: value.gen_lists,
            state: State::Alive,
            last_heartbeat: Instant::now(),
            hb_window: vec![0; HEARTBEAT_WINDOW],
            hb_window_pos: 0,
            hb_sum: 0,
            hb_sq_sum: 0,
            hb_is_full: false,
        }
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}
