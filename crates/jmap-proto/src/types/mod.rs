/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{json::Parser, JsonObjectParser};

pub mod acl;
pub mod any_id;
pub mod blob;
pub mod collection;
pub mod date;
pub mod id;
pub mod keyword;
pub mod pointer;
pub mod property;
pub mod state;
pub mod type_state;
pub mod value;

pub type DocumentId = u32;
pub type ChangeId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeUnparsable<V> {
    Value(V),
    ParseError(String),
}

impl<V: JsonObjectParser> JsonObjectParser for MaybeUnparsable<V> {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self> {
        match V::parse(parser) {
            Ok(value) => Ok(MaybeUnparsable::Value(value)),
            Err(_) if parser.is_eof || parser.skip_string() => Ok(MaybeUnparsable::ParseError(
                String::from_utf8_lossy(parser.bytes[parser.pos_marker..parser.pos - 1].as_ref())
                    .into_owned(),
            )),
            Err(err) => Err(err),
        }
    }
}

// MaybeUnparsable de/serialization
impl<V: serde::Serialize> serde::Serialize for MaybeUnparsable<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MaybeUnparsable::Value(value) => value.serialize(serializer),
            MaybeUnparsable::ParseError(str) => serializer.serialize_str(str),
        }
    }
}
