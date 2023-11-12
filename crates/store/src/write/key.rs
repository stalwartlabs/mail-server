/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::{convert::TryInto, hash::Hasher};
use utils::codec::leb128::Leb128_;

use crate::{
    backend::MAX_TOKEN_MASK, BitmapKey, BlobHash, BlobKey, IndexKey, IndexKeyPrefix, Key, LogKey,
    ValueKey, BLOB_HASH_LEN, SUBSPACE_ACLS, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS,
    SUBSPACE_VALUES, U32_LEN, U64_LEN,
};

use super::{BitmapClass, BlobOp, TagValue, ValueClass};

pub struct KeySerializer {
    buf: Vec<u8>,
}

pub trait KeySerialize {
    fn serialize(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeBigEndian {
    fn deserialize_be_u32(&self, index: usize) -> crate::Result<u32>;
    fn deserialize_be_u64(&self, index: usize) -> crate::Result<u64>;
}

impl KeySerializer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn write<T: KeySerialize>(mut self, value: T) -> Self {
        value.serialize(&mut self.buf);
        self
    }

    pub fn write_leb128<T: Leb128_>(mut self, value: T) -> Self {
        T::to_leb128_bytes(value, &mut self.buf);
        self
    }

    pub fn finalize(self) -> Vec<u8> {
        self.buf
    }
}

impl KeySerialize for u8 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl KeySerialize for &str {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &String {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &[u8] {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl KeySerialize for u32 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u16 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u64 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl DeserializeBigEndian for &[u8] {
    fn deserialize_be_u32(&self, index: usize) -> crate::Result<u32> {
        self.get(index..index + U32_LEN)
            .ok_or_else(|| {
                crate::Error::InternalError(
                    "Index out of range while deserializing u32.".to_string(),
                )
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    crate::Error::InternalError(
                        "Index out of range while deserializing u32.".to_string(),
                    )
                })
            })
            .map(u32::from_be_bytes)
    }

    fn deserialize_be_u64(&self, index: usize) -> crate::Result<u64> {
        self.get(index..index + U64_LEN)
            .ok_or_else(|| {
                crate::Error::InternalError(
                    "Index out of range while deserializing u64.".to_string(),
                )
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    crate::Error::InternalError(
                        "Index out of range while deserializing u64.".to_string(),
                    )
                })
            })
            .map(u64::from_be_bytes)
    }
}

impl<T: AsRef<ValueClass>> ValueKey<T> {
    pub fn property(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
        field: impl Into<u8>,
    ) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            class: ValueClass::Property(field.into()),
        }
    }

    pub fn with_document_id(self, document_id: u32) -> Self {
        Self {
            document_id,
            ..self
        }
    }
}

impl IndexKeyPrefix {
    pub fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        {
            if include_subspace {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            } else {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.field)
        .finalize()
    }
}

impl Key for LogKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_LOGS
    }

    fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        {
            if include_subspace {
                KeySerializer::new(std::mem::size_of::<LogKey>() + 1).write(crate::SUBSPACE_LOGS)
            } else {
                KeySerializer::new(std::mem::size_of::<LogKey>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.change_id)
        .finalize()
    }
}

impl<T: AsRef<ValueClass> + Sync + Send> Key for ValueKey<T> {
    fn subspace(&self) -> u8 {
        if !matches!(self.class.as_ref(), ValueClass::Acl(_)) {
            SUBSPACE_VALUES
        } else {
            SUBSPACE_ACLS
        }
    }

    fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        match self.class.as_ref() {
            ValueClass::Property(field) => if include_subspace {
                KeySerializer::new(U32_LEN * 2 + 3).write(crate::SUBSPACE_VALUES)
            } else {
                KeySerializer::new(U32_LEN * 2 + 2)
            }
            .write(self.account_id)
            .write(self.collection)
            .write_leb128(self.document_id)
            .write(*field),
            ValueClass::Acl(grant_account_id) => if include_subspace {
                KeySerializer::new(U32_LEN * 3 + 2).write(crate::SUBSPACE_ACLS)
            } else {
                KeySerializer::new(U32_LEN * 3 + 1)
            }
            .write(*grant_account_id)
            .write(self.account_id)
            .write(self.collection)
            .write(self.document_id),
            ValueClass::Named(name) => if include_subspace {
                KeySerializer::new(U32_LEN + name.len() + 1).write(crate::SUBSPACE_VALUES)
            } else {
                KeySerializer::new(U32_LEN + name.len())
            }
            .write(u32::MAX)
            .write(name.as_slice()),
        }
        .finalize()
    }
}

impl<T: AsRef<[u8]> + Sync + Send> Key for IndexKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }

    fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        let key = self.key.as_ref();
        {
            if include_subspace {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            } else {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.field)
        .write(key)
        .write(self.document_id)
        .finalize()
    }
}

impl<T: AsRef<BitmapClass> + Sync + Send> Key for BitmapKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_BITMAPS
    }

    fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        const BM_DOCUMENT_IDS: u8 = 0;
        const BM_TAG: u8 = 1 << 5;
        const BM_TEXT: u8 = 1 << 6;

        const TAG_ID: u8 = 0;
        const TAG_TEXT: u8 = 1 << 0;
        const TAG_STATIC: u8 = 1 << 1;

        let ks = if include_subspace {
            KeySerializer::new(self.len() + 1).write(crate::SUBSPACE_BITMAPS)
        } else {
            KeySerializer::new(self.len())
        }
        .write(self.account_id)
        .write(self.collection);

        match self.class.as_ref() {
            BitmapClass::DocumentIds => ks.write(BM_DOCUMENT_IDS),
            BitmapClass::Tag { field, value } => match value {
                TagValue::Id(id) => ks.write(BM_TAG | TAG_ID).write(*field).write_leb128(*id),
                TagValue::Text(text) => ks
                    .write(BM_TAG | TAG_TEXT)
                    .write(*field)
                    .write(text.as_slice()),
                TagValue::Static(id) => ks.write(BM_TAG | TAG_STATIC).write(*field).write(*id),
            },
            BitmapClass::Text { field, token } => ks
                .write(BM_TEXT | (token.len() & MAX_TOKEN_MASK) as u8)
                .write(*field)
                .hash_text(token),
        }
        .write(self.block_num)
        .finalize()
    }
}

impl<T: AsRef<BlobHash> + Sync + Send> Key for BlobKey<T> {
    fn serialize(&self, include_subspace: bool) -> Vec<u8> {
        let ks = {
            if include_subspace {
                KeySerializer::new(BLOB_HASH_LEN + (U64_LEN * 3) + 1).write(crate::SUBSPACE_BLOBS)
            } else {
                KeySerializer::new(BLOB_HASH_LEN + (U64_LEN * 3))
            }
        };

        match self.op {
            BlobOp::Reserve { until, size } => ks
                .write(1u8)
                .write(self.account_id)
                .write::<&[u8]>(self.hash.as_ref().as_ref())
                .write(until)
                .write(size as u32),
            BlobOp::Commit => ks
                .write(0u8)
                .write::<&[u8]>(self.hash.as_ref().as_ref())
                .write(u32::MAX)
                .write(0u8)
                .write(u32::MAX),
            BlobOp::Link => ks
                .write(0u8)
                .write::<&[u8]>(self.hash.as_ref().as_ref())
                .write(self.account_id)
                .write(self.collection)
                .write(self.document_id),
        }
        .finalize()
    }

    fn subspace(&self) -> u8 {
        crate::SUBSPACE_BLOBS
    }
}

const AHASHER: ahash::RandomState = ahash::RandomState::with_seeds(
    0xaf1f2242106c64b3,
    0x60ca4cfb4b3ed0ce,
    0xc7dbc0bb615e82b3,
    0x520ad065378daf88,
);
lazy_static::lazy_static! {
    static ref SIPHASHER: siphasher::sip::SipHasher13 =
        siphasher::sip::SipHasher13::new_with_keys(0x56205cbdba8f02a6, 0xbd0dbc4bb06d687b);
}

impl KeySerializer {
    fn hash_text(mut self, item: impl AsRef<[u8]>) -> Self {
        let item = item.as_ref();

        if item.len() <= 8 {
            self.buf.extend_from_slice(item);
        } else {
            let h1 = xxhash_rust::xxh3::xxh3_64(item).to_le_bytes();
            let h2 = farmhash::hash64(item).to_le_bytes();
            let h3 = AHASHER.hash_one(item).to_le_bytes();
            let mut sh = *SIPHASHER;
            sh.write(item.as_ref());
            let h4 = sh.finish().to_le_bytes();

            match item.len() {
                9..=16 => {
                    self.buf.extend_from_slice(&h1[..2]);
                    self.buf.extend_from_slice(&h2[..2]);
                    self.buf.extend_from_slice(&h3[..2]);
                    self.buf.extend_from_slice(&h4[..2]);
                }
                17..=32 => {
                    self.buf.extend_from_slice(&h1[..3]);
                    self.buf.extend_from_slice(&h2[..3]);
                    self.buf.extend_from_slice(&h3[..3]);
                    self.buf.extend_from_slice(&h4[..3]);
                }
                _ => {
                    self.buf.extend_from_slice(&h1[..4]);
                    self.buf.extend_from_slice(&h2[..4]);
                    self.buf.extend_from_slice(&h3[..4]);
                    self.buf.extend_from_slice(&h4[..4]);
                }
            }
        }
        self
    }
}

impl<T: AsRef<BitmapClass>> BitmapKey<T> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        std::mem::size_of::<BitmapKey<BitmapClass>>()
            + match self.class.as_ref() {
                BitmapClass::DocumentIds => 0,
                BitmapClass::Tag { value, .. } => match value {
                    TagValue::Id(_) => U32_LEN,
                    TagValue::Text(v) => v.len(),
                    TagValue::Static(_) => 1,
                },
                BitmapClass::Text { token, .. } => token.len(),
            }
    }
}

impl<T: AsRef<ValueClass>> ValueKey<T> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        std::mem::size_of::<ValueKey<ValueClass>>()
            + match self.class.as_ref() {
                ValueClass::Property(_) => 1,
                ValueClass::Acl(_) => U32_LEN,
                ValueClass::Named(v) => v.len(),
            }
    }
}
