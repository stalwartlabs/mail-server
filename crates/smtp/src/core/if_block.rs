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

use std::net::{IpAddr, Ipv4Addr};

use crate::config::{
    Condition, ConditionMatch, Conditions, EnvelopeKey, IfBlock, IpAddrMask, StringMatch,
};

use super::Envelope;

impl<T: Default> IfBlock<T> {
    pub async fn eval(&self, envelope: &impl Envelope) -> &T {
        for if_then in &self.if_then {
            if if_then.conditions.eval(envelope).await {
                return &if_then.then;
            }
        }

        &self.default
    }
}

impl Conditions {
    pub async fn eval(&self, envelope: &impl Envelope) -> bool {
        let mut conditions = self.conditions.iter();
        let mut matched = false;

        while let Some(rule) = conditions.next() {
            match rule {
                Condition::Match { key, value, not } => {
                    matched = match value {
                        ConditionMatch::String(value) => {
                            let ctx_value = envelope.key_to_string(key);
                            match value {
                                StringMatch::Equal(value) => value.eq(ctx_value.as_ref()),
                                StringMatch::StartsWith(value) => ctx_value.starts_with(value),
                                StringMatch::EndsWith(value) => ctx_value.ends_with(value),
                            }
                        }
                        ConditionMatch::IpAddrMask(value) => value.matches(&match key {
                            EnvelopeKey::RemoteIp => envelope.remote_ip(),
                            EnvelopeKey::LocalIp => envelope.local_ip(),
                            _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                        }),
                        ConditionMatch::UInt(value) => {
                            *value
                                == if key == &EnvelopeKey::Listener {
                                    envelope.listener_id()
                                } else {
                                    debug_assert!(false, "Invalid value for UInt context key.");
                                    u16::MAX
                                }
                        }
                        ConditionMatch::Int(value) => {
                            *value
                                == if key == &EnvelopeKey::Listener {
                                    envelope.priority()
                                } else {
                                    debug_assert!(false, "Invalid value for UInt context key.");
                                    i16::MAX
                                }
                        }
                        ConditionMatch::Lookup(lookup) => {
                            if let Some(result) =
                                lookup.contains(envelope.key_to_string(key).as_ref()).await
                            {
                                result
                            } else {
                                return false;
                            }
                        }
                        ConditionMatch::Regex(value) => {
                            value.is_match(envelope.key_to_string(key).as_ref())
                        }
                    } ^ not;
                }
                Condition::JumpIfTrue { positions } => {
                    if matched {
                        //TODO use advance_by when stabilized
                        for _ in 0..*positions {
                            conditions.next();
                        }
                    }
                }
                Condition::JumpIfFalse { positions } => {
                    if !matched {
                        //TODO use advance_by when stabilized
                        for _ in 0..*positions {
                            conditions.next();
                        }
                    }
                }
            }
        }

        matched
    }
}

impl IpAddrMask {
    pub fn matches(&self, remote: &IpAddr) -> bool {
        match self {
            IpAddrMask::V4 { addr, mask } => match *mask {
                u32::MAX => match remote {
                    IpAddr::V4(remote) => addr == remote,
                    IpAddr::V6(remote) => {
                        if let Some(remote) = remote.to_ipv4_mapped() {
                            addr == &remote
                        } else {
                            false
                        }
                    }
                },
                0 => {
                    matches!(remote, IpAddr::V4(_))
                }
                _ => {
                    u32::from_be_bytes(match remote {
                        IpAddr::V4(ip) => ip.octets(),
                        IpAddr::V6(ip) => {
                            if let Some(ip) = ip.to_ipv4() {
                                ip.octets()
                            } else {
                                return false;
                            }
                        }
                    }) & mask
                        == u32::from_be_bytes(addr.octets()) & mask
                }
            },
            IpAddrMask::V6 { addr, mask } => match *mask {
                u128::MAX => match remote {
                    IpAddr::V6(remote) => remote == addr,
                    IpAddr::V4(remote) => &remote.to_ipv6_mapped() == addr,
                },
                0 => {
                    matches!(remote, IpAddr::V6(_))
                }
                _ => {
                    u128::from_be_bytes(match remote {
                        IpAddr::V6(ip) => ip.octets(),
                        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    }) & mask
                        == u128::from_be_bytes(addr.octets()) & mask
                }
            },
        }
    }
}
