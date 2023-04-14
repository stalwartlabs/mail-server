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

use std::io::Write;

use store::{BlobHash, BLOB_HASH_LEN};
use utils::codec::{
    base32_custom::Base32Writer,
    leb128::{Leb128Iterator, Leb128Writer},
};

use crate::parser::{base32::JsonBase32Reader, json::Parser, JsonObjectParser};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobId {
    pub hash: BlobHash,
    pub section: Option<BlobSection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobSection {
    pub offset_start: usize,
    pub size: usize,
    pub encoding: u8,
}

impl JsonObjectParser for BlobId {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let encoding = match parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?
        {
            b'a' => None,
            b @ b'b'..=b'g' => Some(b - b'b'),
            _ => {
                return Err(parser.error_value());
            }
        };

        let mut it = JsonBase32Reader::new(parser);
        let mut hash = [0; BLOB_HASH_LEN];

        for byte in hash.iter_mut().take(BLOB_HASH_LEN) {
            *byte = it.next().ok_or_else(|| it.error())?;
        }

        Ok(BlobId {
            hash: BlobHash { hash },
            section: if let Some(encoding) = encoding {
                BlobSection {
                    offset_start: it.next_leb128().ok_or_else(|| it.error())?,
                    size: it.next_leb128().ok_or_else(|| it.error())?,
                    encoding,
                }
                .into()
            } else {
                None
            },
        })
    }
}

impl BlobId {
    pub fn new(hash: BlobHash) -> Self {
        BlobId {
            hash,
            section: None,
        }
    }

    pub fn new_section(
        hash: BlobHash,
        offset_start: usize,
        offset_end: usize,
        encoding: impl Into<u8>,
    ) -> Self {
        BlobId {
            hash,
            section: BlobSection {
                offset_start,
                size: offset_end - offset_start,
                encoding: encoding.into(),
            }
            .into(),
        }
    }

    pub fn start_offset(&self) -> usize {
        if let Some(section) = &self.section {
            section.offset_start
        } else {
            0
        }
    }
}

impl From<&BlobHash> for BlobId {
    fn from(id: &BlobHash) -> Self {
        BlobId::new(*id)
    }
}

impl From<BlobHash> for BlobId {
    fn from(id: BlobHash) -> Self {
        BlobId::new(id)
    }
}

impl Default for BlobId {
    fn default() -> Self {
        Self {
            hash: BlobHash {
                hash: [0; BLOB_HASH_LEN],
            },
            section: None,
        }
    }
}

impl serde::Serialize for BlobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for BlobId {
    #[allow(clippy::unused_io_amount)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writer;
        if let Some(section) = &self.section {
            writer =
                Base32Writer::with_capacity(BLOB_HASH_LEN + (std::mem::size_of::<u32>() * 2) + 1);
            writer.push_char(char::from(b'b' + section.encoding));
            writer.write(&self.hash.hash).unwrap();
            writer.write_leb128(section.offset_start).unwrap();
            writer.write_leb128(section.size).unwrap();
        } else {
            writer = Base32Writer::with_capacity(BLOB_HASH_LEN + 1);
            writer.push_char('a');
            writer.write(&self.hash.hash).unwrap();
        }

        f.write_str(&writer.finalize())
    }
}
