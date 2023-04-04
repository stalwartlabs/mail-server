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

use utils::codec::{
    base32_custom::Base32Writer,
    leb128::{Leb128Iterator, Leb128Writer},
};

use crate::parser::{base32::JsonBase32Reader, json::Parser, JsonObjectParser};

pub const BLOB_HASH_LEN: usize = 32;
pub const BLOB_LOCAL: u8 = 0;
pub const BLOB_EXTERNAL: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BlobHash {
    Local { hash: [u8; BLOB_HASH_LEN] },
    External { hash: [u8; BLOB_HASH_LEN] },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobId {
    pub id: BlobHash,
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
        let (is_local, encoding) = match parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?
        {
            b'b' => (false, None),
            b'a' => (true, None),
            b @ b'c'..=b'g' => (true, Some(b - b'c')),
            b @ b'h'..=b'l' => (false, Some(b - b'h')),
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
            id: if is_local {
                BlobHash::Local { hash }
            } else {
                BlobHash::External { hash }
            },
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
    pub fn new(id: BlobHash) -> Self {
        BlobId { id, section: None }
    }

    pub fn new_section(id: BlobHash, offset_start: usize, offset_end: usize, encoding: u8) -> Self {
        BlobId {
            id,
            section: BlobSection {
                offset_start,
                size: offset_end - offset_start,
                encoding,
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
        BlobId::new(id.clone())
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
            id: BlobHash::Local {
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
            writer.push_char(char::from(if self.id.is_local() {
                b'c' + section.encoding
            } else {
                b'h' + section.encoding
            }));
            writer.write(self.id.hash()).unwrap();
            writer.write_leb128(section.offset_start).unwrap();
            writer.write_leb128(section.size).unwrap();
        } else {
            writer = Base32Writer::with_capacity(BLOB_HASH_LEN + 1);
            writer.push_char(if self.id.is_local() { 'a' } else { 'b' });
            writer.write(self.id.hash()).unwrap();
        }

        f.write_str(&writer.finalize())
    }
}

impl BlobHash {
    /*pub fn new_local(bytes: &[u8]) -> Self {
        // Create blob key
        let mut hasher = Sha256::new();
        hasher.update(bytes);

        BlobId::Local {
            hash: hasher.finalize().into(),
        }
    }

    pub fn new_external(bytes: &[u8]) -> Self {
        // Create blob key
        let mut hasher = Sha256::new();
        hasher.update(bytes);

        BlobId::External {
            hash: hasher.finalize().into(),
        }
    }*/

    pub fn is_local(&self) -> bool {
        matches!(self, BlobHash::Local { .. })
    }

    pub fn is_external(&self) -> bool {
        matches!(self, BlobHash::External { .. })
    }

    pub fn hash(&self) -> &[u8] {
        match self {
            BlobHash::Local { hash } => hash,
            BlobHash::External { hash } => hash,
        }
    }
}
