/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use std::ops::Deref;

use utils::codec::base32_custom::{BASE32_ALPHABET, BASE32_INVERSE};

use crate::{
    parser::{json::Parser, JsonObjectParser},
    request::reference::MaybeReference,
};

use super::DocumentId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub struct Id {
    id: u64,
}

impl Default for Id {
    fn default() -> Self {
        Id { id: u64::MAX }
    }
}

impl JsonObjectParser for Id {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut id = 0;

        while let Some(ch) = parser.next_unescaped()? {
            let i = BASE32_INVERSE[ch as usize];
            if i != u8::MAX {
                id = (id << 5) | i as u64;
            } else {
                return Err(parser.error_value());
            }
        }

        Ok(Id { id })
    }
}

impl JsonObjectParser for MaybeReference<Id, String> {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let ch = parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?;

        if ch != b'#' {
            let mut id = BASE32_INVERSE[ch as usize] as u64;

            if id != u8::MAX as u64 {
                while let Some(ch) = parser.next_unescaped()? {
                    let i = BASE32_INVERSE[ch as usize];
                    if i != u8::MAX {
                        id = (id << 5) | i as u64;
                    } else {
                        return Err(parser.error_value());
                    }
                }

                Ok(MaybeReference::Value(Id { id }))
            } else {
                Err(parser.error_value())
            }
        } else {
            String::parse(parser).map(MaybeReference::Reference)
        }
    }
}

impl Id {
    pub fn new(id: u64) -> Self {
        Self { id }
    }

    pub fn singleton() -> Self {
        Self::new(20080258862541)
    }

    // From https://github.com/archer884/crockford by J/A <archer884@gmail.com>
    // License: MIT/Apache 2.0
    pub fn as_string(&self) -> String {
        match self.id {
            0 => "a".to_string(),
            mut n => {
                // Used for the initial shift.
                const QUAD_SHIFT: usize = 60;
                const QUAD_RESET: usize = 4;

                // Used for all subsequent shifts.
                const FIVE_SHIFT: usize = 59;
                const FIVE_RESET: usize = 5;

                // After we clear the four most significant bits, the four least significant bits will be
                // replaced with 0001. We can then know to stop once the four most significant bits are,
                // likewise, 0001.
                const STOP_BIT: u64 = 1 << QUAD_SHIFT;

                let mut buf = String::with_capacity(7);

                // Start by getting the most significant four bits. We get four here because these would be
                // leftovers when starting from the least significant bits. In either case, tag the four least
                // significant bits with our stop bit.
                match (n >> QUAD_SHIFT) as usize {
                    // Eat leading zero-bits. This should not be done if the first four bits were non-zero.
                    // Additionally, we *must* do this in increments of five bits.
                    0 => {
                        n <<= QUAD_RESET;
                        n |= 1;
                        n <<= n.leading_zeros() / 5 * 5;
                    }

                    // Write value of first four bytes.
                    i => {
                        n <<= QUAD_RESET;
                        n |= 1;
                        buf.push(char::from(BASE32_ALPHABET[i]));
                    }
                }

                // From now until we reach the stop bit, take the five most significant bits and then shift
                // left by five bits.
                while n != STOP_BIT {
                    buf.push(char::from(BASE32_ALPHABET[(n >> FIVE_SHIFT) as usize]));
                    n <<= FIVE_RESET;
                }

                buf
            }
        }
    }

    pub fn from_parts(prefix_id: DocumentId, doc_id: DocumentId) -> Id {
        Id {
            id: (prefix_id as u64) << 32 | doc_id as u64,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn document_id(&self) -> DocumentId {
        (self.id & 0xFFFFFFFF) as DocumentId
    }

    pub fn prefix_id(&self) -> DocumentId {
        (self.id >> 32) as DocumentId
    }

    pub fn is_singleton(&self) -> bool {
        self.id == 20080258862541
    }
}

impl From<u64> for Id {
    fn from(id: u64) -> Self {
        Id { id }
    }
}

impl From<u32> for Id {
    fn from(id: u32) -> Self {
        Id { id: id as u64 }
    }
}

impl From<Id> for u64 {
    fn from(id: Id) -> Self {
        id.id
    }
}

impl From<&Id> for u64 {
    fn from(id: &Id) -> Self {
        id.id
    }
}

impl From<(u32, u32)> for Id {
    fn from(id: (u32, u32)) -> Self {
        Id::from_parts(id.0, id.1)
    }
}

impl Deref for Id {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl AsRef<u64> for Id {
    fn as_ref(&self) -> &u64 {
        &self.id
    }
}

impl From<Id> for u32 {
    fn from(id: Id) -> Self {
        id.document_id()
    }
}

impl From<Id> for String {
    fn from(id: Id) -> Self {
        id.as_string()
    }
}

impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_string().as_str())
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::{parser::json::Parser, types::id::Id};

    #[test]
    fn parse_jmap_id() {
        for number in [
            0,
            1,
            10,
            1000,
            Id::singleton().id,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let id = Id::from(number);
            assert_eq!(
                Parser::new(format!("\"{id}\"").as_bytes())
                    .next_token::<Id>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap(),
                id
            );
        }

        Parser::new(b"\"p333333333333p333333333333\"")
            .next_token::<Id>()
            .unwrap()
            .unwrap_string("")
            .unwrap();
    }
}
