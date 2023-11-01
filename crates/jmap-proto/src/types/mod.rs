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
