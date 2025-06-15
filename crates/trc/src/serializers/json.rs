/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Error, Event, EventDetails, Key, Value};
use ahash::AHashSet;
use base64::{Engine, engine::general_purpose::STANDARD};
use mail_parser::DateTime;
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};

struct Keys<'x> {
    keys: &'x [(Key, Value)],
    span_keys: &'x [(Key, Value)],
}

pub struct JsonEventSerializer<T> {
    inner: T,
    with_id: bool,
    with_spans: bool,
    with_description: bool,
    with_explanation: bool,
}

impl<T> JsonEventSerializer<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            with_id: false,
            with_spans: false,
            with_description: false,
            with_explanation: false,
        }
    }

    pub fn with_id(mut self) -> Self {
        self.with_id = true;
        self
    }

    pub fn with_spans(mut self) -> Self {
        self.with_spans = true;
        self
    }

    pub fn with_description(mut self) -> Self {
        self.with_description = true;
        self
    }

    pub fn with_explanation(mut self) -> Self {
        self.with_explanation = true;
        self
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsRef<Event<EventDetails>>> Serialize for JsonEventSerializer<Vec<T>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.inner.len()))?;
        for event in &self.inner {
            seq.serialize_element(&JsonEventSerializer {
                inner: event,
                with_id: self.with_id,
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
            })?;
        }
        seq.end()
    }
}

impl<T: AsRef<Event<EventDetails>>> Serialize for JsonEventSerializer<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let event = self.inner.as_ref();
        let mut map = serializer.serialize_map(None)?;
        if self.with_id {
            map.serialize_entry(
                "id",
                &format!("{}{}", event.inner.timestamp, event.inner.typ.id()),
            )?;
        }
        if self.with_description {
            map.serialize_entry("text", event.inner.typ.description())?;
        }
        if self.with_explanation {
            map.serialize_entry("details", event.inner.typ.explain())?;
        }
        map.serialize_entry(
            "createdAt",
            &DateTime::from_timestamp(event.inner.timestamp as i64).to_rfc3339(),
        )?;
        map.serialize_entry("type", event.inner.typ.name())?;
        map.serialize_entry(
            "data",
            &JsonEventSerializer {
                inner: Keys {
                    keys: event.keys.as_slice(),
                    span_keys: event
                        .inner
                        .span
                        .as_ref()
                        .map(|s| &s.keys[..])
                        .unwrap_or(&[]),
                },
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
                with_id: self.with_id,
            },
        )?;
        map.end()
    }
}

impl Serialize for JsonEventSerializer<Keys<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let keys_len = self.inner.keys.len() + self.inner.span_keys.len();
        let mut seen_keys = AHashSet::with_capacity(keys_len);
        let mut keys = serializer.serialize_map(Some(keys_len))?;
        for (key, value) in self.inner.keys.iter().chain(self.inner.span_keys.iter()) {
            if !matches!(value, Value::None)
                && (self.with_spans || !matches!(key, Key::SpanId))
                && seen_keys.insert(*key)
            {
                keys.serialize_entry(
                    key.name(),
                    &JsonEventSerializer {
                        inner: value,
                        with_spans: self.with_spans,
                        with_description: self.with_description,
                        with_explanation: self.with_explanation,
                        with_id: self.with_id,
                    },
                )?;
            }
        }
        keys.end()
    }
}

impl Serialize for JsonEventSerializer<&Error> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", self.inner.0.inner.name())?;
        if self.with_description {
            map.serialize_entry("text", self.inner.0.inner.description())?;
        }
        if self.with_explanation {
            map.serialize_entry("details", self.inner.0.inner.explain())?;
        }
        map.serialize_entry(
            "data",
            &JsonEventSerializer {
                inner: Keys {
                    keys: self.inner.0.keys.as_slice(),
                    span_keys: &[],
                },
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
                with_id: self.with_id,
            },
        )?;
        map.end()
    }
}

impl Serialize for JsonEventSerializer<&Value> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.inner {
            Value::String(value) => value.serialize(serializer),
            Value::UInt(value) => value.serialize(serializer),
            Value::Int(value) => value.serialize(serializer),
            Value::Float(value) => value.serialize(serializer),
            Value::Timestamp(value) => DateTime::from_timestamp(*value as i64)
                .to_rfc3339()
                .serialize(serializer),
            Value::Duration(value) => value.serialize(serializer),
            Value::Bytes(value) => STANDARD.encode(value).serialize(serializer),
            Value::Bool(value) => value.serialize(serializer),
            Value::Ipv4(value) => value.serialize(serializer),
            Value::Ipv6(value) => value.serialize(serializer),
            Value::Event(value) => JsonEventSerializer {
                inner: value,
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
                with_id: self.with_id,
            }
            .serialize(serializer),
            Value::Array(value) => JsonEventSerializer {
                inner: value,
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
                with_id: self.with_id,
            }
            .serialize(serializer),
            Value::None => unreachable!(),
        }
    }
}

impl Serialize for JsonEventSerializer<&Vec<Value>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.inner.len()))?;
        for value in self.inner {
            seq.serialize_element(&JsonEventSerializer {
                inner: value,
                with_spans: self.with_spans,
                with_description: self.with_description,
                with_explanation: self.with_explanation,
                with_id: self.with_id,
            })?;
        }
        seq.end()
    }
}
