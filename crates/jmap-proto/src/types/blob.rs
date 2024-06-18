/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
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

use std::borrow::Borrow;

use store::{
    write::{DeserializeFrom, SerializeInto},
    BlobClass,
};
use utils::{
    codec::{
        base32_custom::{Base32Reader, Base32Writer},
        leb128::{Leb128Iterator, Leb128Writer},
    },
    BlobHash,
};

use crate::parser::{base32::JsonBase32Reader, json::Parser, JsonObjectParser};

const B_LINKED: u8 = 0x10;
const B_RESERVED: u8 = 0x20;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct BlobId {
    pub hash: BlobHash,
    pub class: BlobClass,
    pub section: Option<BlobSection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
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
        let mut it = JsonBase32Reader::new(parser);
        BlobId::from_iter(&mut it).ok_or_else(|| it.error())
    }
}

impl BlobId {
    pub fn new(hash: BlobHash, class: BlobClass) -> Self {
        BlobId {
            hash,
            class,
            section: None,
        }
    }

    pub fn new_section(
        hash: BlobHash,
        class: BlobClass,
        offset_start: usize,
        offset_end: usize,
        encoding: impl Into<u8>,
    ) -> Self {
        BlobId {
            hash,
            class,
            section: BlobSection {
                offset_start,
                size: offset_end - offset_start,
                encoding: encoding.into(),
            }
            .into(),
        }
    }

    pub fn with_section_size(mut self, size: usize) -> Self {
        self.section.get_or_insert_with(Default::default).size = size;
        self
    }

    pub fn from_base32(value: impl AsRef<[u8]>) -> Option<Self> {
        BlobId::from_iter(&mut Base32Reader::new(value.as_ref()))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T, U>(it: &mut T) -> Option<Self>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        let class = *it.next()?.borrow();
        let encoding = class & 0x0F;

        let mut hash = BlobHash::default();
        for byte in hash.as_mut().iter_mut() {
            *byte = *it.next()?.borrow();
        }

        let account_id: u32 = it.next_leb128()?;

        BlobId {
            hash,
            class: if (class & B_LINKED) != 0 {
                BlobClass::Linked {
                    account_id,
                    collection: *it.next()?.borrow(),
                    document_id: it.next_leb128()?,
                }
            } else {
                BlobClass::Reserved {
                    account_id,
                    expires: it.next_leb128()?,
                }
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

    fn serialize_as(&self, writer: &mut impl Leb128Writer) {
        let marker = self
            .section
            .as_ref()
            .map_or(0, |section| section.encoding + 1)
            | if matches!(
                self,
                BlobId {
                    class: BlobClass::Linked { .. },
                    ..
                }
            ) {
                B_LINKED
            } else {
                B_RESERVED
            };

        let _ = writer.write(&[marker]);
        let _ = writer.write(self.hash.as_ref());

        match &self.class {
            BlobClass::Reserved {
                account_id,
                expires,
            } => {
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write_leb128(*expires);
            }
            BlobClass::Linked {
                account_id,
                collection,
                document_id,
            } => {
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write(&[*collection]);
                let _ = writer.write_leb128(*document_id);
            }
        }

        if let Some(section) = &self.section {
            let _ = writer.write_leb128(section.offset_start);
            let _ = writer.write_leb128(section.size);
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
