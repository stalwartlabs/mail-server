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

use std::{
    collections::HashSet,
    hash::Hash,
    slice::Iter,
    time::{Duration, SystemTime},
};

use nlp::tokenizers::word::WordTokenizer;
use utils::{
    codec::leb128::{Leb128Iterator, Leb128Vec},
    BlobHash,
};

use crate::{backend::MAX_TOKEN_LENGTH, BlobClass, Deserialize, Serialize, Value};

use self::assert::AssertValue;

pub mod assert;
pub mod assign_id;
pub mod batch;
pub mod bitmap;
pub mod blob;
pub mod hash;
pub mod key;
pub mod log;
pub mod purge;

#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 10;
#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 1000;
#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

pub const F_VALUE: u32 = 1 << 0;
pub const F_INDEX: u32 = 1 << 1;
pub const F_BITMAP: u32 = 1 << 2;
pub const F_CLEAR: u32 = 1 << 3;

#[derive(Debug)]
pub struct Batch {
    pub ops: Vec<Operation>,
}

#[derive(Debug)]
pub struct BatchBuilder {
    pub ops: Vec<Operation>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    AccountId {
        account_id: u32,
    },
    Collection {
        collection: u8,
    },
    DocumentId {
        document_id: u32,
    },
    AssertValue {
        class: ValueClass,
        assert_value: AssertValue,
    },
    Value {
        class: ValueClass,
        op: ValueOp,
    },
    Index {
        field: u8,
        key: Vec<u8>,
        set: bool,
    },
    Bitmap {
        class: BitmapClass,
        set: bool,
    },
    Log {
        change_id: u64,
        collection: u8,
        set: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BitmapClass {
    DocumentIds,
    Tag { field: u8, value: TagValue },
    Text { field: u8, token: BitmapHash },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapHash {
    pub hash: [u8; 8],
    pub len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TagValue {
    Id(u32),
    Text(Vec<u8>),
    Static(u8),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ValueClass {
    Property(u8),
    Acl(u32),
    Lookup(LookupClass),
    TermIndex,
    ReservedId,
    Directory(DirectoryClass),
    Blob(BlobOp),
    IndexEmail(u64),
    Config(Vec<u8>),
    Queue(QueueClass),
    Report(ReportClass),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum LookupClass {
    Key(Vec<u8>),
    Counter(Vec<u8>),
    CounterExpiry(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DirectoryClass {
    NameToId(Vec<u8>),
    EmailToId(Vec<u8>),
    MemberOf { principal_id: u32, member_of: u32 },
    Members { principal_id: u32, has_member: u32 },
    Domain(Vec<u8>),
    Principal(u32),
    UsedQuota(u32),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum QueueClass {
    Message(u64),
    MessageEvent(QueueEvent),
    DmarcReportHeader(ReportEvent),
    DmarcReportEvent(ReportEvent),
    TlsReportHeader(ReportEvent),
    TlsReportEvent(ReportEvent),
    QuotaCount(Vec<u8>),
    QuotaSize(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ReportClass {
    Tls { id: u64, expires: u64 },
    Dmarc { id: u64, expires: u64 },
    Arf { id: u64, expires: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct QueueEvent {
    pub due: u64,
    pub queue_id: u64,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct ReportEvent {
    pub due: u64,
    pub policy_hash: u64,
    pub seq_id: u64,
    pub domain: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Default)]
pub enum ValueOp {
    Set(Vec<u8>),
    AtomicAdd(i64),
    AddAndGet(i64),
    #[default]
    Clear,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum BlobOp {
    Reserve { hash: BlobHash, until: u64 },
    Commit { hash: BlobHash },
    Link { hash: BlobHash },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyKey<T: AsRef<[u8]>> {
    pub subspace: u8,
    pub key: T,
}

impl From<u32> for TagValue {
    fn from(value: u32) -> Self {
        TagValue::Id(value)
    }
}

impl From<Vec<u8>> for TagValue {
    fn from(value: Vec<u8>) -> Self {
        TagValue::Text(value)
    }
}

impl From<String> for TagValue {
    fn from(value: String) -> Self {
        TagValue::Text(value.into_bytes())
    }
}

impl From<u8> for TagValue {
    fn from(value: u8) -> Self {
        TagValue::Static(value)
    }
}

impl From<()> for TagValue {
    fn from(_: ()) -> Self {
        TagValue::Text(vec![])
    }
}

impl Serialize for u32 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for u64 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for i64 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for u16 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for f64 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for &str {
    fn serialize(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Serialize for &String {
    fn serialize(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Serialize for String {
    fn serialize(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl Serialize for Vec<u8> {
    fn serialize(self) -> Vec<u8> {
        self
    }
}

impl Deserialize for String {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            crate::Error::InternalError("Failed to deserialize u64".to_string())
        })?))
    }
}

impl Deserialize for i64 {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
            crate::Error::InternalError("Failed to deserialize i64".to_string())
        })?))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            crate::Error::InternalError("Failed to deserialize u32".to_string())
        })?))
    }
}

pub trait SerializeInto {
    fn serialize_into(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeFrom: Sized {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl<T: SerializeInto> Serialize for &Vec<T> {
    fn serialize(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len() * 4);
        bytes.push_leb128(self.len());
        for item in self {
            item.serialize_into(&mut bytes);
        }
        bytes
    }
}

impl<T: SerializeInto> Serialize for Vec<T> {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl SerializeInto for String {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.len());
        if !self.is_empty() {
            buf.extend_from_slice(self.as_bytes());
        }
    }
}

impl SerializeInto for Vec<u8> {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.len());
        if !self.is_empty() {
            buf.extend_from_slice(self.as_slice());
        }
    }
}

impl SerializeInto for u32 {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(*self);
    }
}

impl SerializeInto for u64 {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(*self);
    }
}

impl DeserializeFrom for u32 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for u64 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for String {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        <Vec<u8>>::deserialize_from(bytes).and_then(|s| String::from_utf8(s).ok())
    }
}

impl DeserializeFrom for Vec<u8> {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let len: usize = bytes.next_leb128()?;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(*bytes.next()?);
        }
        buf.into()
    }
}

impl<T: DeserializeFrom + Sync + Send> Deserialize for Vec<T> {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| crate::Error::InternalError("Failed to deserialize Vec".to_string()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(T::deserialize_from(&mut bytes).ok_or_else(|| {
                crate::Error::InternalError("Failed to deserialize Vec".to_string())
            })?);
        }
        Ok(list)
    }
}

trait HasFlag {
    fn has_flag(&self, flag: u32) -> bool;
}

impl HasFlag for u32 {
    #[inline(always)]
    fn has_flag(&self, flag: u32) -> bool {
        self & flag == flag
    }
}

pub trait ToBitmaps {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool);
}

pub trait TokenizeText {
    fn tokenize_into(&self, tokens: &mut HashSet<String>);
    fn to_tokens(&self) -> HashSet<String>;
}

impl ToBitmaps for &str {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        let mut tokens = HashSet::new();

        self.tokenize_into(&mut tokens);

        for token in tokens {
            ops.push(Operation::Bitmap {
                class: BitmapClass::Text {
                    field,
                    token: BitmapHash::new(token),
                },
                set,
            });
        }
    }
}

impl TokenizeText for &str {
    fn tokenize_into(&self, tokens: &mut HashSet<String>) {
        for token in WordTokenizer::new(self, MAX_TOKEN_LENGTH) {
            tokens.insert(token.word.into_owned());
        }
    }

    fn to_tokens(&self) -> HashSet<String> {
        let mut tokens = HashSet::new();
        self.tokenize_into(&mut tokens);
        tokens
    }
}

impl ToBitmaps for String {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        self.as_str().to_bitmaps(ops, field, set)
    }
}

impl ToBitmaps for u32 {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field,
                value: TagValue::Id(*self),
            },
            set,
        });
    }
}

impl ToBitmaps for u64 {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field,
                value: TagValue::Id(*self as u32),
            },
            set,
        });
    }
}

impl ToBitmaps for f64 {
    fn to_bitmaps(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl<T: ToBitmaps> ToBitmaps for Vec<T> {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        for item in self {
            item.to_bitmaps(ops, field, set);
        }
    }
}

impl Serialize for () {
    fn serialize(self) -> Vec<u8> {
        Vec::with_capacity(0)
    }
}

impl ToBitmaps for () {
    fn to_bitmaps(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl Deserialize for () {
    fn deserialize(_bytes: &[u8]) -> crate::Result<Self> {
        Ok(())
    }
}

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder);
}

impl Operation {
    pub fn acl(grant_account_id: u32, set: Option<Vec<u8>>) -> Self {
        Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: set.map(ValueOp::Set).unwrap_or(ValueOp::Clear),
        }
    }
}

#[inline(always)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl AsRef<ValueClass> for ValueClass {
    fn as_ref(&self) -> &ValueClass {
        self
    }
}

impl AsRef<BitmapClass> for BitmapClass {
    fn as_ref(&self) -> &BitmapClass {
        self
    }
}

impl BitmapClass {
    pub fn tag_id(property: impl Into<u8>, id: u32) -> Self {
        BitmapClass::Tag {
            field: property.into(),
            value: TagValue::Id(id),
        }
    }
}

impl AsRef<BlobClass> for BlobClass {
    fn as_ref(&self) -> &BlobClass {
        self
    }
}

impl BlobClass {
    pub fn account_id(&self) -> u32 {
        match self {
            BlobClass::Reserved { account_id, .. } | BlobClass::Linked { account_id, .. } => {
                *account_id
            }
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            BlobClass::Reserved { expires, .. } => *expires > now(),
            BlobClass::Linked { .. } => true,
        }
    }
}

#[derive(Debug)]
pub struct Bincode<T: serde::Serialize + serde::de::DeserializeOwned> {
    pub inner: T,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Bincode<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> From<Value<'static>> for Bincode<T> {
    fn from(_: Value<'static>) -> Self {
        unreachable!("From Value called on Bincode<T>")
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Serialize for &Bincode<T> {
    fn serialize(self) -> Vec<u8> {
        lz4_flex::compress_prepend_size(&bincode::serialize(&self.inner).unwrap_or_default())
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Serialize for Bincode<T> {
    fn serialize(self) -> Vec<u8> {
        lz4_flex::compress_prepend_size(&bincode::serialize(&self.inner).unwrap_or_default())
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned + Sized + Sync + Send> Deserialize
    for Bincode<T>
{
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        lz4_flex::decompress_size_prepended(bytes)
            .map_err(|err| {
                crate::Error::InternalError(format!("Bincode decompression failed: {err:?}"))
            })
            .and_then(|result| {
                bincode::deserialize(&result).map_err(|err| {
                    crate::Error::InternalError(format!(
                        "Bincode deserialization failed (len {}): {err:?}",
                        result.len()
                    ))
                })
            })
            .map(|inner| Self { inner })
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> ToBitmaps for Bincode<T> {
    fn to_bitmaps(&self, _ops: &mut Vec<crate::write::Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> ToBitmaps for &Bincode<T> {
    fn to_bitmaps(&self, _ops: &mut Vec<crate::write::Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}
