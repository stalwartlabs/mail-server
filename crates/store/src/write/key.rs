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
use utils::{codec::leb128::Leb128_, BLOB_HASH_LEN};

use crate::{
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, Key, LogKey, ValueKey, SUBSPACE_ACL,
    SUBSPACE_BITMAP_ID, SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT, SUBSPACE_BLOB_LINK,
    SUBSPACE_BLOB_RESERVE, SUBSPACE_COUNTER, SUBSPACE_DIRECTORY, SUBSPACE_FTS_INDEX,
    SUBSPACE_FTS_QUEUE, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_LOOKUP_VALUE, SUBSPACE_PROPERTY,
    SUBSPACE_QUEUE_EVENT, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUOTA, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SUBSPACE_SETTINGS, U32_LEN, U64_LEN, WITH_SUBSPACE,
};

use super::{
    AnyKey, AssignedIds, BitmapClass, BlobOp, DirectoryClass, LookupClass, QueueClass, ReportClass,
    ReportEvent, ResolveId, TagValue, ValueClass,
};

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

impl<T: AsRef<ValueClass<u32>>> ValueKey<T> {
    pub fn property(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
        field: impl Into<u8>,
    ) -> ValueKey<ValueClass<u32>> {
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

    pub fn is_counter(&self) -> bool {
        self.class.as_ref().is_counter(self.collection)
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

impl<T: AsRef<ValueClass<u32>> + Sync + Send> Key for ValueKey<T> {
    fn subspace(&self) -> u8 {
        self.class.as_ref().subspace(self.collection)
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        self.class.as_ref().serialize(
            self.account_id,
            self.collection,
            self.document_id,
            flags,
            None,
        )
    }
}

impl<T: ResolveId> ValueClass<T> {
    pub fn serialize(
        &self,
        account_id: u32,
        collection: u8,
        document_id: u32,
        flags: u32,
        assigned_ids: Option<&AssignedIds>,
    ) -> Vec<u8> {
        let serializer = if (flags & WITH_SUBSPACE) != 0 {
            KeySerializer::new(self.serialized_size() + 2).write(self.subspace(collection))
        } else {
            KeySerializer::new(self.serialized_size() + 1)
        };

        match self {
            ValueClass::Property(field) => serializer
                .write(account_id)
                .write(collection)
                .write(*field)
                .write(document_id),
            ValueClass::FtsIndex(hash) => {
                let serializer = serializer.write(account_id).write(
                    hash.hash
                        .get(0..std::cmp::min(hash.len as usize, 8))
                        .unwrap(),
                );

                if hash.len >= 8 {
                    serializer.write(hash.len)
                } else {
                    serializer
                }
                .write(collection)
                .write(document_id)
            }
            ValueClass::Acl(grant_account_id) => serializer
                .write(*grant_account_id)
                .write(account_id)
                .write(collection)
                .write(document_id),
            ValueClass::FtsQueue(queue) => serializer
                .write(queue.seq)
                .write(account_id)
                .write(collection)
                .write(document_id)
                .write::<&[u8]>(queue.hash.as_ref()),
            ValueClass::Blob(op) => match op {
                BlobOp::Reserve { hash, until } => serializer
                    .write(account_id)
                    .write::<&[u8]>(hash.as_ref())
                    .write(*until),
                BlobOp::Commit { hash } => serializer
                    .write::<&[u8]>(hash.as_ref())
                    .write(u32::MAX)
                    .write(0u8)
                    .write(u32::MAX),
                BlobOp::Link { hash } => serializer
                    .write::<&[u8]>(hash.as_ref())
                    .write(account_id)
                    .write(collection)
                    .write(document_id),
                BlobOp::LinkId { hash, id } => serializer
                    .write::<&[u8]>(hash.as_ref())
                    .write((*id >> 32) as u32)
                    .write(u8::MAX)
                    .write(*id as u32),
            },
            ValueClass::Config(key) => serializer.write(key.as_slice()),
            ValueClass::Lookup(lookup) => match lookup {
                LookupClass::Key(key) => serializer.write(key.as_slice()),
                LookupClass::Counter(key) => serializer.write(key.as_slice()),
            },
            ValueClass::Directory(directory) => match directory {
                DirectoryClass::NameToId(name) => serializer.write(0u8).write(name.as_slice()),
                DirectoryClass::EmailToId(email) => serializer.write(1u8).write(email.as_slice()),
                DirectoryClass::Principal(uid) => serializer
                    .write(2u8)
                    .write_leb128(uid.resolve_id(assigned_ids)),
                DirectoryClass::Domain(name) => serializer.write(3u8).write(name.as_slice()),
                DirectoryClass::UsedQuota(uid) => serializer.write(4u8).write_leb128(*uid),
                DirectoryClass::MemberOf {
                    principal_id,
                    member_of,
                } => serializer
                    .write(5u8)
                    .write(principal_id.resolve_id(assigned_ids))
                    .write(member_of.resolve_id(assigned_ids)),
                DirectoryClass::Members {
                    principal_id,
                    has_member,
                } => serializer
                    .write(6u8)
                    .write(principal_id.resolve_id(assigned_ids))
                    .write(has_member.resolve_id(assigned_ids)),
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(queue_id) => serializer.write(*queue_id),
                QueueClass::MessageEvent(event) => {
                    serializer.write(event.due).write(event.queue_id)
                }
                QueueClass::DmarcReportHeader(event) => serializer
                    .write(0u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id)
                    .write(0u8),
                QueueClass::TlsReportHeader(event) => serializer
                    .write(0u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id)
                    .write(1u8),
                QueueClass::DmarcReportEvent(event) => serializer
                    .write(1u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id),
                QueueClass::TlsReportEvent(event) => serializer
                    .write(2u8)
                    .write(event.due)
                    .write(event.domain.as_bytes())
                    .write(event.policy_hash)
                    .write(event.seq_id),
                QueueClass::QuotaCount(key) => serializer.write(0u8).write(key.as_slice()),
                QueueClass::QuotaSize(key) => serializer.write(1u8).write(key.as_slice()),
            },
            ValueClass::Report(report) => match report {
                ReportClass::Tls { id, expires } => {
                    serializer.write(0u8).write(*expires).write(*id)
                }
                ReportClass::Dmarc { id, expires } => {
                    serializer.write(1u8).write(*expires).write(*id)
                }
                ReportClass::Arf { id, expires } => {
                    serializer.write(2u8).write(*expires).write(*id)
                }
            },
            ValueClass::Any(any) => serializer.write(any.key.as_slice()),
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

impl<T: AsRef<BitmapClass<u32>> + Sync + Send> Key for BitmapKey<T> {
    fn subspace(&self) -> u8 {
        self.class.as_ref().subspace()
    }

    fn serialize(&self, flags: u32) -> Vec<u8> {
        self.class.as_ref().serialize(
            self.account_id,
            self.collection,
            self.document_id,
            flags,
            None,
        )
    }
}

impl<T: ResolveId> BitmapClass<T> {
    pub fn subspace(&self) -> u8 {
        match self {
            BitmapClass::DocumentIds => SUBSPACE_BITMAP_ID,
            BitmapClass::Tag { .. } => SUBSPACE_BITMAP_TAG,
            BitmapClass::Text { .. } => SUBSPACE_BITMAP_TEXT,
        }
    }

    pub fn serialize(
        &self,
        account_id: u32,
        collection: u8,
        document_id: u32,
        flags: u32,
        assigned_ids: Option<&AssignedIds>,
    ) -> Vec<u8> {
        const BM_MARKER: u8 = 1 << 7;

        match self {
            BitmapClass::DocumentIds => if (flags & WITH_SUBSPACE) != 0 {
                KeySerializer::new(U32_LEN + 2).write(SUBSPACE_BITMAP_ID)
            } else {
                KeySerializer::new(U32_LEN + 1)
            }
            .write(account_id)
            .write(collection),
            BitmapClass::Tag { field, value } => match value {
                TagValue::Id(id) => if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new((U32_LEN * 2) + 4).write(SUBSPACE_BITMAP_TAG)
                } else {
                    KeySerializer::new((U32_LEN * 2) + 3)
                }
                .write(account_id)
                .write(collection)
                .write(*field)
                .write_leb128(id.resolve_id(assigned_ids)),
                TagValue::Text(text) => if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new(U32_LEN + 4 + text.len()).write(SUBSPACE_BITMAP_TAG)
                } else {
                    KeySerializer::new(U32_LEN + 3 + text.len())
                }
                .write(account_id)
                .write(collection)
                .write(*field | BM_MARKER)
                .write(text.as_slice()),
            },
            BitmapClass::Text { field, token } => {
                let serializer = if (flags & WITH_SUBSPACE) != 0 {
                    KeySerializer::new(U32_LEN + 16 + 3 + 1).write(SUBSPACE_BITMAP_TEXT)
                } else {
                    KeySerializer::new(U32_LEN + 16 + 3)
                }
                .write(account_id)
                .write(
                    token
                        .hash
                        .get(0..std::cmp::min(token.len as usize, 8))
                        .unwrap(),
                );

                if token.len >= 8 {
                    serializer.write(token.len)
                } else {
                    serializer
                }
                .write(collection)
                .write(*field)
            }
        }
        .write(document_id)
        .finalize()
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

impl<T> ValueClass<T> {
    pub fn serialized_size(&self) -> usize {
        match self {
            ValueClass::Property(_) => U32_LEN * 2 + 3,
            ValueClass::FtsIndex(hash) => {
                if hash.len >= 8 {
                    U32_LEN * 2 + 10
                } else {
                    hash.len as usize + U32_LEN * 2 + 1
                }
            }
            ValueClass::Acl(_) => U32_LEN * 3 + 2,
            ValueClass::Lookup(LookupClass::Counter(v) | LookupClass::Key(v))
            | ValueClass::Config(v) => v.len(),
            ValueClass::Directory(d) => match d {
                DirectoryClass::NameToId(v)
                | DirectoryClass::EmailToId(v)
                | DirectoryClass::Domain(v) => v.len(),
                DirectoryClass::Principal(_) | DirectoryClass::UsedQuota(_) => U32_LEN,
                DirectoryClass::Members { .. } | DirectoryClass::MemberOf { .. } => U32_LEN * 2,
            },
            ValueClass::Blob(op) => match op {
                BlobOp::Reserve { .. } => BLOB_HASH_LEN + U64_LEN + U32_LEN + 1,
                BlobOp::Commit { .. } | BlobOp::Link { .. } | BlobOp::LinkId { .. } => {
                    BLOB_HASH_LEN + U32_LEN * 2 + 2
                }
            },
            ValueClass::FtsQueue { .. } => BLOB_HASH_LEN + U64_LEN * 2,
            ValueClass::Queue(q) => match q {
                QueueClass::Message(_) => U64_LEN,
                QueueClass::MessageEvent(_) => U64_LEN * 2,
                QueueClass::DmarcReportEvent(event) | QueueClass::TlsReportEvent(event) => {
                    event.domain.len() + U64_LEN * 3
                }
                QueueClass::DmarcReportHeader(event) | QueueClass::TlsReportHeader(event) => {
                    event.domain.len() + (U64_LEN * 3) + 1
                }
                QueueClass::QuotaCount(v) | QueueClass::QuotaSize(v) => v.len(),
            },
            ValueClass::Report(_) => U64_LEN * 2 + 1,
            ValueClass::Any(v) => v.key.len(),
        }
    }

    pub fn subspace(&self, collection: u8) -> u8 {
        match self {
            ValueClass::Property(field) => {
                if *field == 84 && collection == 1 {
                    SUBSPACE_COUNTER
                } else {
                    SUBSPACE_PROPERTY
                }
            }
            ValueClass::Acl(_) => SUBSPACE_ACL,
            ValueClass::FtsIndex(_) => SUBSPACE_FTS_INDEX,
            ValueClass::FtsQueue { .. } => SUBSPACE_FTS_QUEUE,
            ValueClass::Blob(op) => match op {
                BlobOp::Reserve { .. } => SUBSPACE_BLOB_RESERVE,
                BlobOp::Commit { .. } | BlobOp::Link { .. } | BlobOp::LinkId { .. } => {
                    SUBSPACE_BLOB_LINK
                }
            },
            ValueClass::Config(_) => SUBSPACE_SETTINGS,
            ValueClass::Lookup(lookup) => match lookup {
                LookupClass::Key(_) => SUBSPACE_LOOKUP_VALUE,
                LookupClass::Counter(_) => SUBSPACE_COUNTER,
            },
            ValueClass::Directory(directory) => match directory {
                DirectoryClass::UsedQuota(_) => SUBSPACE_QUOTA,
                _ => SUBSPACE_DIRECTORY,
            },
            ValueClass::Queue(queue) => match queue {
                QueueClass::Message(_) => SUBSPACE_QUEUE_MESSAGE,
                QueueClass::MessageEvent(_) => SUBSPACE_QUEUE_EVENT,
                QueueClass::DmarcReportHeader(_)
                | QueueClass::TlsReportHeader(_)
                | QueueClass::DmarcReportEvent(_)
                | QueueClass::TlsReportEvent(_) => SUBSPACE_REPORT_OUT,
                QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_) => SUBSPACE_QUOTA,
            },
            ValueClass::Report(_) => SUBSPACE_REPORT_IN,
            ValueClass::Any(any) => any.subspace,
        }
    }

    pub fn is_counter(&self, collection: u8) -> bool {
        match self {
            ValueClass::Directory(DirectoryClass::UsedQuota(_))
            | ValueClass::Lookup(LookupClass::Counter(_))
            | ValueClass::Queue(QueueClass::QuotaCount(_) | QueueClass::QuotaSize(_)) => true,
            ValueClass::Property(84) if collection == 1 => true, // TODO: Find a more elegant way to do this
            _ => false,
        }
    }
}

impl From<ValueClass<u32>> for ValueKey<ValueClass<u32>> {
    fn from(class: ValueClass<u32>) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class,
        }
    }
}

impl From<DirectoryClass<u32>> for ValueKey<ValueClass<u32>> {
    fn from(value: DirectoryClass<u32>) -> Self {
        ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Directory(value),
        }
    }
}

impl<U> From<DirectoryClass<U>> for ValueClass<U> {
    fn from(value: DirectoryClass<U>) -> Self {
        ValueClass::Directory(value)
    }
}

impl<U> From<BlobOp> for ValueClass<U> {
    fn from(value: BlobOp) -> Self {
        ValueClass::Blob(value)
    }
}

impl Deserialize for ReportEvent {
    fn deserialize(key: &[u8]) -> crate::Result<Self> {
        Ok(ReportEvent {
            due: key.deserialize_be_u64(1)?,
            policy_hash: key.deserialize_be_u64(key.len() - (U64_LEN * 2 + 1))?,
            seq_id: key.deserialize_be_u64(key.len() - (U64_LEN + 1))?,
            domain: key
                .get(U64_LEN + 1..key.len() - (U64_LEN * 2 + 1))
                .and_then(|domain| std::str::from_utf8(domain).ok())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    crate::Error::InternalError(format!(
                        "Failed to deserialize report domain: {key:?}"
                    ))
                })?,
        })
    }
}
