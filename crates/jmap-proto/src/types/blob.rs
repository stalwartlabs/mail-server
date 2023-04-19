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

use std::{borrow::Borrow, io::Write};

use store::{
    rand::{self, Rng},
    write::{now, DeserializeFrom, SerializeInto},
    BlobKind,
};
use utils::codec::{
    base32_custom::Base32Writer,
    leb128::{Leb128Iterator, Leb128Writer},
};

use crate::parser::{base32::JsonBase32Reader, json::Parser, JsonObjectParser};

use super::date::UTCDate;

const B_LINKED: u8 = 0x10;
const B_LINKED_MAILDIR: u8 = 0x20;
const B_TEMPORARY: u8 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobId {
    pub kind: BlobKind,
    pub section: Option<BlobSection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlobSection {
    pub offset_start: usize,
    pub size: usize,
    pub encoding: u8,
}

impl BlobId {
    pub fn maildir(account_id: u32, document_id: u32) -> Self {
        Self {
            kind: BlobKind::LinkedMaildir {
                account_id,
                document_id,
            },
            section: None,
        }
    }

    pub fn temporary(account_id: u32) -> Self {
        let now_secs = now();
        let now = UTCDate::from_timestamp(now_secs as i64);

        Self {
            kind: BlobKind::Temporary {
                account_id,
                creation_year: now.year,
                creation_month: now.month,
                creation_day: now.day,
                seq: ((now_secs % 86400) as u32) << 15
                    | rand::thread_rng().gen_range(0u32..=32767u32),
            },
            section: None,
        }
    }

    pub fn has_access(&self, account_id: u32) -> bool {
        match &self.kind {
            BlobKind::Linked { account_id: a, .. } => *a == account_id,
            BlobKind::LinkedMaildir { account_id: a, .. } => *a == account_id,
            BlobKind::Temporary { account_id: a, .. } => *a == account_id,
        }
    }
}

impl JsonObjectParser for BlobId {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut it = JsonBase32Reader::new(parser);
        BlobId::from_iter(&mut it).ok_or_else(|| it.error())
    }
}

impl BlobId {
    pub fn new(kind: BlobKind) -> Self {
        BlobId {
            kind,
            section: None,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T, U>(it: &mut T) -> Option<Self>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        let kind = *it.next()?.borrow();
        let encoding = kind & 0x0F;

        BlobId {
            kind: match kind & 0xF0 {
                B_LINKED => BlobKind::Linked {
                    account_id: it.next_leb128()?,
                    collection: *it.next()?.borrow(),
                    document_id: it.next_leb128()?,
                },
                B_LINKED_MAILDIR => BlobKind::LinkedMaildir {
                    account_id: it.next_leb128()?,
                    document_id: it.next_leb128()?,
                },
                B_TEMPORARY => BlobKind::Temporary {
                    account_id: it.next_leb128()?,
                    creation_year: u16::from_be_bytes([*it.next()?.borrow(), *it.next()?.borrow()]),
                    creation_month: *it.next()?.borrow(),
                    creation_day: *it.next()?.borrow(),
                    seq: it.next_leb128()?,
                },
                _ => return None,
            },
            section: if encoding != 0 {
                BlobSection {
                    offset_start: it.next_leb128()?,
                    size: it.next_leb128()?,
                    encoding: encoding - 1,
                }
                .into()
            } else {
                None
            },
        }
        .into()
    }

    fn serialize_as(&self, writer: &mut (impl Write + Leb128Writer)) {
        let kind = self
            .section
            .as_ref()
            .map_or(0, |section| section.encoding + 1);
        match &self.kind {
            BlobKind::Linked {
                account_id,
                collection,
                document_id,
            } => {
                let _ = writer.write(&[kind | B_LINKED]);
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write(&[*collection]);
                let _ = writer.write_leb128(*document_id);
            }
            BlobKind::LinkedMaildir {
                account_id,
                document_id,
            } => {
                let _ = writer.write(&[kind | B_LINKED_MAILDIR]);
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write_leb128(*document_id);
            }
            BlobKind::Temporary {
                account_id,
                creation_year,
                creation_month,
                creation_day,
                seq,
            } => {
                let _ = writer.write(&[kind | B_TEMPORARY]);
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write(&creation_year.to_be_bytes()[..]);
                let _ = writer.write(&[*creation_month]);
                let _ = writer.write(&[*creation_day]);
                let _ = writer.write_leb128(*seq);
            }
        }

        if let Some(section) = &self.section {
            let _ = writer.write_leb128(section.offset_start);
            let _ = writer.write_leb128(section.size);
        }
    }

    pub fn new_section(
        kind: BlobKind,
        offset_start: usize,
        offset_end: usize,
        encoding: impl Into<u8>,
    ) -> Self {
        BlobId {
            kind,
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

impl Default for BlobId {
    fn default() -> Self {
        BlobId {
            kind: store::BlobKind::LinkedMaildir {
                account_id: u32::MAX,
                document_id: u32::MAX,
            },
            section: None,
        }
    }
}

impl From<&BlobKind> for BlobId {
    fn from(kind: &BlobKind) -> Self {
        BlobId::new(*kind)
    }
}

impl From<BlobKind> for BlobId {
    fn from(id: BlobKind) -> Self {
        BlobId::new(id)
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
        let mut writer = Base32Writer::with_capacity(std::mem::size_of::<BlobId>() * 2);
        self.serialize_as(&mut writer);
        f.write_str(&writer.finalize())
    }
}

impl SerializeInto for BlobId {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        self.serialize_as(buf)
    }
}

impl DeserializeFrom for BlobId {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        BlobId::from_iter(bytes)
    }
}
