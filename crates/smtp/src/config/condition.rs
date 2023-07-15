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

use std::net::IpAddr;

use regex::Regex;

use crate::config::StringMatch;

use super::{Condition, ConditionMatch, Conditions, ConfigContext, EnvelopeKey, IpAddrMask};
use utils::config::{
    utils::{AsKey, ParseKey, ParseValue},
    Config,
};

pub trait ConfigCondition {
    fn parse_condition(
        &self,
        key: impl AsKey,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Conditions>;
    #[cfg(feature = "test_mode")]
    fn parse_conditions(
        &self,
        ctx: &ConfigContext,
    ) -> super::Result<ahash::AHashMap<String, Conditions>>;
}

impl ConfigCondition for Config {
    fn parse_condition(
        &self,
        key_: impl AsKey,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Conditions> {
        let mut conditions = Vec::new();
        let mut stack = Vec::new();
        let mut iter = None;
        let mut jmp_pos = Vec::new();
        let mut prefix = key_.as_key();
        let mut is_all = false;
        let mut is_not = false;

        'outer: loop {
            let mut op_str = "";

            for key in self.sub_keys(prefix.as_str()) {
                if !["if", "then"].contains(&key) {
                    if op_str.is_empty() {
                        op_str = key;
                    } else {
                        return Err(format!(
                            "Multiple operations found for condition {prefix:?}.",
                        ));
                    }
                }
            }

            if op_str.is_empty() {
                return Err(format!("Missing operation for condition {prefix:?}."));
            } else if ["any-of", "all-of", "none-of"].contains(&op_str) {
                stack.push((
                    std::mem::replace(
                        &mut iter,
                        self.sub_keys((&prefix, op_str).as_key()).peekable().into(),
                    ),
                    (&prefix, op_str).as_key(),
                    std::mem::take(&mut jmp_pos),
                    is_all,
                    is_not,
                ));

                match op_str {
                    "any-of" => {
                        if !is_not {
                            is_all = false;
                            is_not = false;
                        } else {
                            is_all = true;
                            is_not = true;
                        }
                    }
                    "all-of" => {
                        if !is_not {
                            is_all = true;
                            is_not = false;
                        } else {
                            is_all = false;
                            is_not = true;
                        }
                    }
                    _ => {
                        is_not = !is_not;
                        if !is_not {
                            is_all = true;
                            is_not = false;
                        } else {
                            is_all = false;
                            is_not = true;
                        }
                    }
                }
            } else {
                let key = self.property_require::<EnvelopeKey>((&prefix, "if"))?;
                if !available_keys.contains(&key) {
                    return Err(format!(
                        "Envelope key {key:?} is not available in this context for property {prefix:?}",
                    ));
                }

                enum MatchType {
                    Equal,
                    Regex,
                    Lookup,
                    StartsWith,
                    EndsWith,
                }

                let (op, op_is_not) = match op_str {
                    "eq" | "equal-to" | "ne" | "not-equal-to" => {
                        (MatchType::Equal, op_str == "ne" || op_str == "not-equal-to")
                    }
                    "in-list" | "not-in-list" => (MatchType::Lookup, op_str == "not-in-list"),
                    "matches" | "not-matches" => (MatchType::Regex, op_str.starts_with("not-")),
                    "starts-with" | "not-starts-with" => {
                        (MatchType::StartsWith, op_str == "not-starts-with")
                    }
                    "ends-with" | "not-ends-with" => {
                        (MatchType::EndsWith, op_str == "not-ends-with")
                    }
                    _ => {
                        return Err(format!("Invalid operation {op_str:?} for key {prefix:?}."));
                    }
                };

                let value_str = self.value_require((&prefix, op_str))?;
                let value = match (key, &op) {
                    (EnvelopeKey::Listener, MatchType::Equal) => {
                        ConditionMatch::UInt(if value_str != "sieve" {
                            ctx.servers
                                .iter()
                                .find_map(|s| {
                                    if s.id == value_str {
                                        s.internal_id.into()
                                    } else {
                                        None
                                    }
                                })
                                .ok_or_else(|| {
                                    format!(
                                        "Listener {:?} does not exist for property {:?}.",
                                        value_str,
                                        (&prefix, op_str).as_key()
                                    )
                                })?
                        } else {
                            u16::MAX
                        })
                    }
                    (EnvelopeKey::LocalIp | EnvelopeKey::RemoteIp, MatchType::Equal) => {
                        ConditionMatch::IpAddrMask(value_str.parse_key((&prefix, op_str))?)
                    }
                    (EnvelopeKey::Priority, MatchType::Equal) => {
                        ConditionMatch::Int(value_str.parse_key((&prefix, op_str))?)
                    }
                    (
                        EnvelopeKey::Recipient
                        | EnvelopeKey::RecipientDomain
                        | EnvelopeKey::Sender
                        | EnvelopeKey::SenderDomain
                        | EnvelopeKey::AuthenticatedAs
                        | EnvelopeKey::Mx
                        | EnvelopeKey::LocalIp
                        | EnvelopeKey::RemoteIp,
                        _,
                    ) => match op {
                        MatchType::Equal => {
                            ConditionMatch::String(StringMatch::Equal(value_str.to_string()))
                        }
                        MatchType::StartsWith => {
                            ConditionMatch::String(StringMatch::StartsWith(value_str.to_string()))
                        }
                        MatchType::EndsWith => {
                            ConditionMatch::String(StringMatch::EndsWith(value_str.to_string()))
                        }
                        MatchType::Regex => {
                            ConditionMatch::Regex(Regex::new(value_str).map_err(|err| {
                                format!(
                                    "Failed to compile regular expression {:?} for key {:?}: {}.",
                                    value_str,
                                    (&prefix, value_str).as_key(),
                                    err
                                )
                            })?)
                        }
                        MatchType::Lookup => {
                            if let Some(lookup) = ctx.directory.lookups.get(value_str) {
                                ConditionMatch::Lookup(lookup.clone())
                            } else {
                                return Err(format!(
                                    "Lookup {:?} not found for property {:?}.",
                                    value_str,
                                    (&prefix, value_str).as_key()
                                ));
                            }
                        }
                    },
                    _ => {
                        return Err(format!(
                            "Invalid 'op'/'value' combination for key {:?}.",
                            key_.as_key()
                        ));
                    }
                };
                conditions.push(Condition::Match {
                    key,
                    value,
                    not: is_not ^ op_is_not,
                });
                if iter.as_mut().map_or(false, |it| it.peek().is_some()) {
                    jmp_pos.push(conditions.len());
                    conditions.push(if is_all {
                        Condition::JumpIfFalse {
                            positions: usize::MAX,
                        }
                    } else {
                        Condition::JumpIfTrue {
                            positions: usize::MAX,
                        }
                    });
                }
            }

            loop {
                if let Some(array_pos) = iter.as_mut().and_then(|it| it.next()) {
                    prefix = (stack.last().unwrap().1.as_str(), array_pos).as_key();
                    break;
                } else if let Some((prev_iter, _, prev_jmp_pos, prev_is_all, prev_is_not)) =
                    stack.pop()
                {
                    let cur_pos = conditions.len() - 1;
                    for pos in jmp_pos {
                        if let Condition::JumpIfFalse { positions }
                        | Condition::JumpIfTrue { positions } = &mut conditions[pos]
                        {
                            *positions = cur_pos - pos;
                        }
                    }

                    iter = prev_iter;
                    jmp_pos = prev_jmp_pos;
                    is_all = prev_is_all;
                    is_not = prev_is_not;
                } else {
                    break 'outer;
                }
            }
        }

        Ok(Conditions { conditions })
    }

    #[cfg(feature = "test_mode")]
    fn parse_conditions(
        &self,
        ctx: &ConfigContext,
    ) -> super::Result<ahash::AHashMap<String, Conditions>> {
        use ahash::AHashMap;
        let mut conditions = AHashMap::new();
        let available_keys = vec![
            EnvelopeKey::Recipient,
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::Priority,
            EnvelopeKey::Mx,
        ];

        for rule_name in self.sub_keys("rule") {
            conditions.insert(
                rule_name.to_string(),
                self.parse_condition(("rule", rule_name), ctx, &available_keys)?,
            );
        }

        Ok(conditions)
    }
}

impl ParseValue for IpAddrMask {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((addr, mask)) = value.rsplit_once('/') {
            if let (Ok(addr), Ok(mask)) =
                (addr.trim().parse::<IpAddr>(), mask.trim().parse::<u32>())
            {
                match addr {
                    IpAddr::V4(addr) if (8..=32).contains(&mask) => {
                        return Ok(IpAddrMask::V4 {
                            addr,
                            mask: u32::MAX << (32 - mask),
                        })
                    }
                    IpAddr::V6(addr) if (8..=128).contains(&mask) => {
                        return Ok(IpAddrMask::V6 {
                            addr,
                            mask: u128::MAX << (128 - mask),
                        })
                    }
                    _ => (),
                }
            }
        } else {
            match value.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(addr)) => {
                    return Ok(IpAddrMask::V4 {
                        addr,
                        mask: u32::MAX,
                    })
                }
                Ok(IpAddr::V6(addr)) => {
                    return Ok(IpAddrMask::V6 {
                        addr,
                        mask: u128::MAX,
                    })
                }
                _ => (),
            }
        }

        Err(format!(
            "Invalid IP address {:?} for property {:?}.",
            value,
            key.as_key()
        ))
    }
}
