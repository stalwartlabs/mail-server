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

use std::convert::TryInto;
use utils::codec::leb128::Leb128_;

use crate::{
    BitmapKey, IndexKey, IndexKeyPrefix, Key, LogKey, ValueKey, BLOB_HASH_LEN, SUBSPACE_BITMAPS,
    SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_VALUES, U32_LEN, U64_LEN, WITHOUT_BLOCK_NUM,
    WITH_SUBSPACE,
};

use super::{AnyKey, BitmapClass, BlobOp, DirectoryClass, TagValue, ValueClass};

pub struct KeySerializer {
    pub buf: Vec<u8>,
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

impl Key for IndexKeyPrefix {
    fn serialize(&self, flags: u32) -> Vec<u8> {
        {
            if (flags & WITH_SUBSPACE) != 0 {
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

    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }
}

impl IndexKeyPrefix {
    pub fn len() -> usize {
        U32_LEN + 2
    }
}

impl Key for LogKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_LOGS
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        {
            if (flags & WITH_SUBSPACE) != 0 {
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
        SUBSPACE_VALUES
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::new(self.class.as_ref().serialized_size() + 2).write(self.subspace())
        } else {
            KeySerializer::new(self.class.as_ref().serialized_size() + 1)
        };

        match self.class.as_ref() {
            ValueClass::Property(field) => serializer
                .write(0u8)
                .write(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(*field),
            ValueClass::TermIndex => serializer
                .write(1u8)
                .write(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id),
            ValueClass::Acl(grant_account_id) => serializer
                .write(2u8)
                .write(*grant_account_id)
                .write(self.account_id)
                .write(self.collection)
                .write(self.document_id),
            ValueClass::ReservedId => serializer
                .write(3u8)
                .write(self.account_id)
                .write(self.collection)
                .write(self.document_id),
            ValueClass::Key(key) => serializer.write(4u8).write(key.as_slice()),
            ValueClass::IndexEmail(seq) => serializer
                .write(5u8)
                .write(*seq)
                .write(self.account_id)
                .write(self.document_id),
            ValueClass::Blob(op) => match op {
                BlobOp::Reserve { hash, until } => serializer
                    .write(6u8)
                    .write(self.account_id)
                    .write::<&[u8]>(hash.as_ref())
                    .write(*until),
                BlobOp::Commit { hash } => serializer
                    .write(7u8)
                    .write::<&[u8]>(hash.as_ref())
                    .write(u32::MAX)
                    .write(0u8)
                    .write(u32::MAX),
                BlobOp::Link { hash } => serializer
                    .write(7u8)
                    .write::<&[u8]>(hash.as_ref())
                    .write(self.account_id)
                    .write(self.collection)
                    .write(self.document_id),
            },
            ValueClass::Directory(directory) => match directory {
                DirectoryClass::NameToId(name) => serializer.write(20u8).write(name.as_slice()),
                DirectoryClass::EmailToId(email) => serializer.write(21u8).write(email.as_slice()),
                DirectoryClass::Principal(uid) => serializer.write(22u8).write_leb128(*uid),
                DirectoryClass::Domain(name) => serializer.write(23u8).write(name.as_slice()),
                DirectoryClass::UsedQuota(uid) => serializer.write(24u8).write_leb128(*uid),
                DirectoryClass::MemberOf {
                    principal_id,
                    member_of,
                } => serializer
                    .write(25u8)
                    .write(*principal_id)
                    .write(*member_of),
                DirectoryClass::Members {
                    principal_id,
                    has_member,
                } => serializer
                    .write(26u8)
                    .write(*principal_id)
                    .write(*has_member),
            },
        }
        .finalize()
    }
}

impl<T: AsRef<[u8]> + Sync + Send> Key for IndexKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        let key = self.key.as_ref();
        {
            if (flags & WITH_SUBSPACE) != 0 {
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

    fn serialize(&self, flags: u32) -> Vec<u8> {
        const BM_DOCUMENT_IDS: u8 = 0;
        const BM_TAG: u8 = 1 << 6;
        const BM_TEXT: u8 = 1 << 7;

        const TAG_ID: u8 = 0;
        const TAG_TEXT: u8 = 1 << 0;
        const TAG_STATIC: u8 = 1 << 1;

        let serializer = match self.class.as_ref() {
            BitmapClass::DocumentIds => if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(U32_LEN + 3).write(SUBSPACE_BITMAPS)
            } else {
                KeySerializer::new(U32_LEN + 2)
            }
            .write(self.account_id)
            .write(self.collection)
            .write(BM_DOCUMENT_IDS),
            BitmapClass::Tag { field, value } => match value {
                TagValue::Id(id) => if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new((U32_LEN * 2) + 4).write(SUBSPACE_BITMAPS)
                } else {
                    KeySerializer::new((U32_LEN * 2) + 3)
                }
                .write(self.account_id)
                .write(self.collection)
                .write(BM_TAG | TAG_ID)
                .write(*field)
                .write_leb128(*id),
                TagValue::Text(text) => if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new(U32_LEN + 4 + text.len()).write(SUBSPACE_BITMAPS)
                } else {
                    KeySerializer::new(U32_LEN + 3 + text.len())
                }
                .write(self.account_id)
                .write(self.collection)
                .write(BM_TAG | TAG_TEXT)
                .write(*field)
                .write(text.as_slice()),
                TagValue::Static(id) => if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new(U32_LEN + 5).write(SUBSPACE_BITMAPS)
                } else {
                    KeySerializer::new(U32_LEN + 4)
                }
                .write(self.account_id)
                .write(self.collection)
                .write(BM_TAG | TAG_STATIC)
                .write(*field)
                .write(*id),
            },
            BitmapClass::Text { field, token } => if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(U32_LEN + 16 + 3 + 1).write(SUBSPACE_BITMAPS)
            } else {
                KeySerializer::new(U32_LEN + 16 + 3)
            }
            .write(self.account_id)
            .write(self.collection)
            .write(BM_TEXT | token.len)
            .write(*field)
            .write(token.hash.as_slice()),
        };

        if (flags & WITHOUT_BLOCK_NUM) != 0 {
            serializer.finalize()
        } else {
            serializer.write(self.block_num).finalize()
        }
    }
}

impl<T: AsRef<[u8]> + Sync + Send> Key for AnyKey<T> {
    fn serialize(&self, flags: u32) -> Vec<u8> {
        let key = self.key.as_ref();
        if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::new(key.len() + 1).write(self.subspace)
        } else {
            KeySerializer::new(key.len())
        }
        .write(key)
        .finalize()
    }

    fn subspace(&self) -> u8 {
        self.subspace
    }
}

impl ValueClass {
    pub fn serialized_size(&self) -> usize {
        match self {
            ValueClass::Property(_) | ValueClass::TermIndex | ValueClass::ReservedId => {
                U32_LEN * 2 + 3
            }
            ValueClass::Acl(_) => U32_LEN * 3 + 2,
            ValueClass::Key(v) => v.len(),
            ValueClass::Directory(d) => match d {
                DirectoryClass::NameToId(v)
                | DirectoryClass::EmailToId(v)
                | DirectoryClass::Domain(v) => v.len(),
                DirectoryClass::Principal(_) | DirectoryClass::UsedQuota(_) => U32_LEN,
                DirectoryClass::Members { .. } | DirectoryClass::MemberOf { .. } => U32_LEN * 2,
            },
            ValueClass::Blob(op) => match op {
                BlobOp::Reserve { .. } => BLOB_HASH_LEN + U64_LEN + U32_LEN + 1,
                BlobOp::Commit { .. } | BlobOp::Link { .. } => BLOB_HASH_LEN + U32_LEN * 2 + 2,
            },
            ValueClass::IndexEmail { .. } => U64_LEN * 2,
        }
    }
}

impl From<ValueClass> for ValueKey<ValueClass> {
    fn from(class: ValueClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class,
        }
    }
}

impl From<DirectoryClass> for ValueKey<ValueClass> {
    fn from(value: DirectoryClass) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Directory(value),
        }
    }
}

impl From<DirectoryClass> for ValueClass {
    fn from(value: DirectoryClass) -> Self {
        ValueClass::Directory(value)
    }
}

impl From<BlobOp> for ValueClass {
    fn from(value: BlobOp) -> Self {
        ValueClass::Blob(value)
    }
}
