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

use std::{borrow::Cow, net::IpAddr, sync::Arc};

use utils::config::{DynValue, KeyLookup};

use crate::config::{
    Condition, ConditionMatch, Conditions, EnvelopeKey, IfBlock, IpAddrMask, MaybeDynValue,
    StringMatch,
};

pub struct Captures<'x, T> {
    value: &'x T,
    captures: Vec<String>,
}

impl<T: Default> IfBlock<T> {
    pub async fn eval(&self, envelope: &impl KeyLookup<Key = EnvelopeKey>) -> &T {
        for if_then in &self.if_then {
            if if_then.conditions.eval(envelope).await {
                return &if_then.then;
            }
        }

        &self.default
    }

    pub async fn eval_and_capture(
        &self,
        envelope: &impl KeyLookup<Key = EnvelopeKey>,
    ) -> Captures<'_, T> {
        for if_then in &self.if_then {
            if let Some(captures) = if_then.conditions.eval_and_capture(envelope).await {
                return Captures {
                    value: &if_then.then,
                    captures,
                };
            }
        }

        Captures {
            value: &self.default,
            captures: vec![],
        }
    }
}

impl Conditions {
    pub async fn eval(&self, envelope: &impl KeyLookup<Key = EnvelopeKey>) -> bool {
        let mut conditions = self.conditions.iter();
        let mut matched = false;

        while let Some(rule) = conditions.next() {
            match rule {
                Condition::Match { key, value, not } => {
                    matched = match value {
                        ConditionMatch::String(value) => {
                            let ctx_value = envelope.key(key);
                            match value {
                                StringMatch::Equal(value) => value.eq(ctx_value.as_ref()),
                                StringMatch::StartsWith(value) => ctx_value.starts_with(value),
                                StringMatch::EndsWith(value) => ctx_value.ends_with(value),
                            }
                        }
                        ConditionMatch::IpAddrMask(value) => {
                            value.matches(&envelope.key_as_ip(key))
                        }
                        ConditionMatch::UInt(value) => *value == envelope.key_as_int(key) as u16,
                        ConditionMatch::Int(value) => *value == envelope.key_as_int(key) as i16,
                        ConditionMatch::Lookup(lookup) => {
                            if let Some(result) = lookup.contains(envelope.key(key).as_ref()).await
                            {
                                result
                            } else {
                                return false;
                            }
                        }
                        ConditionMatch::Regex(value) => value.is_match(envelope.key(key).as_ref()),
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

    pub async fn eval_and_capture(
        &self,
        envelope: &impl KeyLookup<Key = EnvelopeKey>,
    ) -> Option<Vec<String>> {
        let mut conditions = self.conditions.iter();
        let mut matched = false;
        let mut last_capture = vec![];
        let mut regex_capture = vec![];

        while let Some(rule) = conditions.next() {
            match rule {
                Condition::Match { key, value, not } => {
                    let ctx_value = envelope.key(key);
                    matched = match value {
                        ConditionMatch::String(value) => match value {
                            StringMatch::Equal(value) => value.eq(ctx_value.as_ref()),
                            StringMatch::StartsWith(value) => ctx_value.starts_with(value),
                            StringMatch::EndsWith(value) => ctx_value.ends_with(value),
                        },
                        ConditionMatch::IpAddrMask(value) => {
                            value.matches(&envelope.key_as_ip(key))
                        }
                        ConditionMatch::UInt(value) => *value == envelope.key_as_int(key) as u16,
                        ConditionMatch::Int(value) => *value == envelope.key_as_int(key) as i16,
                        ConditionMatch::Lookup(lookup) => {
                            lookup.contains(ctx_value.as_ref()).await?
                        }
                        ConditionMatch::Regex(value) => {
                            regex_capture.clear();

                            for captures in value.captures_iter(ctx_value.as_ref()) {
                                for capture in captures.iter() {
                                    regex_capture
                                        .push(capture.map_or("", |m| m.as_str()).to_string());
                                }
                            }

                            !regex_capture.is_empty()
                        }
                    } ^ not;

                    // Save last capture
                    if matched {
                        last_capture = if regex_capture.is_empty() {
                            vec![ctx_value.into_owned()]
                        } else {
                            std::mem::take(&mut regex_capture)
                        };
                    }
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

        if matched {
            Some(last_capture)
        } else {
            None
        }
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

impl<'x> Captures<'x, DynValue<EnvelopeKey>> {
    pub fn into_value(self, keys: &'x impl KeyLookup<Key = EnvelopeKey>) -> Cow<'x, str> {
        self.value.apply(self.captures, keys)
    }
}

impl<'x> Captures<'x, Option<DynValue<EnvelopeKey>>> {
    pub fn into_value(self, keys: &'x impl KeyLookup<Key = EnvelopeKey>) -> Option<Cow<'x, str>> {
        self.value.as_ref().map(|v| v.apply(self.captures, keys))
    }
}

impl<'x, T: ?Sized> Captures<'x, MaybeDynValue<T>> {
    pub fn into_value(self, keys: &impl KeyLookup<Key = EnvelopeKey>) -> Option<Arc<T>> {
        match &self.value {
            MaybeDynValue::Dynamic { eval, items } => {
                let r = eval.apply(self.captures, keys);

                match items.get(r.as_ref()) {
                    Some(value) => value.clone().into(),
                    None => {
                        tracing::warn!(
                            context = "eval",
                            event = "error",
                            expression = ?eval,
                            result = ?r,
                            "Failed to resolve rule: value {r:?} not found in item list",
                        );
                        None
                    }
                }
            }
            MaybeDynValue::Static(value) => value.clone().into(),
        }
    }
}

impl<'x, T: ?Sized> Captures<'x, Vec<MaybeDynValue<T>>> {
    pub fn into_value(self, keys: &impl KeyLookup<Key = EnvelopeKey>) -> Vec<Arc<T>> {
        let mut results = Vec::with_capacity(self.value.len());
        for value in self.value.iter() {
            match value {
                MaybeDynValue::Dynamic { eval, items } => {
                    let r = eval.apply_borrowed(&self.captures, keys);
                    match items.get(r.as_ref()) {
                        Some(value) => {
                            results.push(value.clone());
                        }
                        None => {
                            tracing::warn!(
                                context = "eval",
                                event = "error",
                                expression = ?eval,
                                result = ?r,
                                "Failed to resolve rule: value {r:?} not found in item list",
                            );
                        }
                    }
                }
                MaybeDynValue::Static(value) => {
                    results.push(value.clone());
                }
            }
        }
        results
    }
}

impl<'x, T: ?Sized> Captures<'x, Option<MaybeDynValue<T>>> {
    pub fn into_value(self, keys: &impl KeyLookup<Key = EnvelopeKey>) -> Option<Arc<T>> {
        match self.value.as_ref()? {
            MaybeDynValue::Dynamic { eval, items } => {
                let r = eval.apply(self.captures, keys);
                match items.get(r.as_ref()) {
                    Some(value) => value.clone().into(),
                    None => {
                        tracing::warn!(
                            context = "eval",
                            event = "error",
                            expression = ?eval,
                            result = ?r,
                            "Failed to resolve rule: value {r:?} not found in item list",
                        );
                        None
                    }
                }
            }
            MaybeDynValue::Static(value) => value.clone().into(),
        }
    }
}
