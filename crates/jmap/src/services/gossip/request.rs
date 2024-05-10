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

use crate::auth::SymmetricEncrypt;

use super::{EpochId, PeerStatus};

use std::net::IpAddr;
use utils::codec::leb128::Leb128_;

#[derive(Debug)]
pub enum Request {
    Ping(Vec<PeerStatus>),
    Pong(Vec<PeerStatus>),
    Leave(Vec<PeerStatus>),
}

impl Request {
    const PING: u8 = 0;
    const PONG: u8 = 1;
    const LEAVE: u8 = 2;

    pub fn from_bytes(bytes: &[u8]) -> Option<Request> {
        let mut it = bytes.iter();
        let flags = it.next().copied()?;
        let is_ipv6 = flags & (1 << 7) != 0;

        let mut peers = Vec::with_capacity(bytes.len() / std::mem::size_of::<PeerStatus>());
        'outer: loop {
            let addr = if !is_ipv6 {
                let mut octets = [0u8; 4];
                for octet in octets.iter_mut() {
                    if let Some(byte) = it.next() {
                        *octet = *byte;
                    } else {
                        break 'outer;
                    }
                }
                IpAddr::V4(octets.into())
            } else {
                let mut octets = [0u8; 16];
                for octet in octets.iter_mut() {
                    if let Some(byte) = it.next() {
                        *octet = *byte;
                    } else {
                        break 'outer;
                    }
                }
                IpAddr::V6(octets.into())
            };

            peers.push(PeerStatus {
                addr,
                epoch: EpochId::from_leb128_it(&mut it)?,
                gen_config: it.next().copied()?,
                gen_lists: it.next().copied()?,
            });
        }
        match flags & !(1 << 7) {
            0 => Request::Ping(peers),
            1 => Request::Pong(peers),
            2 => Request::Leave(peers),
            _ => return None,
        }
        .into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let (mut flag, peers) = match self {
            Request::Ping(peers) => (Self::PING, peers),
            Request::Pong(peers) => (Self::PONG, peers),
            Request::Leave(peers) => (Self::LEAVE, peers),
        };

        debug_assert!(!peers.is_empty());

        let mut bytes = Vec::with_capacity(
            std::mem::size_of::<usize>()
                + (peers.len() * std::mem::size_of::<PeerStatus>())
                + SymmetricEncrypt::ENCRYPT_TAG_LEN,
        );

        let is_ipv6 = peers.iter().any(|peer| peer.addr.is_ipv6());
        if is_ipv6 {
            flag |= 1 << 7;
        }

        bytes.push(flag);

        for peer in peers {
            if !is_ipv6 {
                match &peer.addr {
                    IpAddr::V4(addr) => bytes.extend_from_slice(addr.octets().as_slice()),
                    IpAddr::V6(_) => unreachable!(),
                }
            } else {
                match &peer.addr {
                    IpAddr::V6(addr) => bytes.extend_from_slice(addr.octets().as_slice()),
                    IpAddr::V4(addr) => {
                        bytes.extend_from_slice(addr.to_ipv6_mapped().octets().as_slice())
                    }
                }
            }

            peer.epoch.to_leb128_bytes(&mut bytes);
            bytes.push(peer.gen_config);
            bytes.push(peer.gen_lists);
        }

        bytes
    }
}
