/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use mail_parser::DateTime;
use serde::{ser::SerializeMap, Serialize, Serializer};

use crate::{Event, EventDetails, EventType, Key, Value};

struct Keys<'x> {
    keys: &'x [(Key, Value)],
    span_keys: &'x [(Key, Value)],
}

impl Serialize for Event<EventDetails> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(
            "id",
            &format!("{}{}", self.inner.timestamp, self.inner.typ.id()),
        )?;
        map.serialize_entry(
            "createdAt",
            &DateTime::from_timestamp(self.inner.timestamp as i64).to_rfc3339(),
        )?;
        map.serialize_entry("type", self.inner.typ.name())?;
        map.serialize_entry(
            "data",
            &Keys {
                keys: self.keys.as_slice(),
                span_keys: self.inner.span.as_ref().map(|s| &s.keys[..]).unwrap_or(&[]),
            },
        )?;
        map.end()
    }
}

impl<'x> Serialize for Keys<'x> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let keys_len = self.keys.len() + self.span_keys.len();
        let mut seen_keys = AHashSet::with_capacity(keys_len);
        let mut keys = serializer.serialize_map(Some(keys_len))?;
        for (key, value) in self.span_keys.iter().chain(self.keys.iter()) {
            if !matches!(value, Value::None)
                && !matches!(key, Key::SpanId)
                && seen_keys.insert(*key)
            {
                keys.serialize_entry(key.name(), value)?;
            }
        }
        keys.end()
    }
}

impl Serialize for Event<EventType> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("type", self.inner.name())?;
        map.serialize_entry(
            "data",
            &Keys {
                keys: self.keys.as_slice(),
                span_keys: &[],
            },
        )?;
        map.end()
    }
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Value::Static(value) => value.serialize(serializer),
            Value::String(value) => value.serialize(serializer),
            Value::UInt(value) => value.serialize(serializer),
            Value::Int(value) => value.serialize(serializer),
            Value::Float(value) => value.serialize(serializer),
            Value::Timestamp(value) => DateTime::from_timestamp(*value as i64)
                .to_rfc3339()
                .serialize(serializer),
            Value::Duration(value) => value.serialize(serializer),
            Value::Bytes(value) => value.serialize(serializer),
            Value::Bool(value) => value.serialize(serializer),
            Value::Ipv4(value) => value.serialize(serializer),
            Value::Ipv6(value) => value.serialize(serializer),
            Value::Protocol(value) => value.name().serialize(serializer),
            Value::Event(value) => value.serialize(serializer),
            Value::Array(value) => value.serialize(serializer),
            Value::None => unreachable!(),
        }
    }
}
