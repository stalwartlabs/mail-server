/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    collections::HashSet,
    fmt::{self, Formatter},
    hash::Hash,
    slice::Iter,
    time::{Duration, SystemTime},
};

use nlp::tokenizers::word::WordTokenizer;
use rand::Rng;
use roaring::RoaringBitmap;
use utils::{
    codec::leb128::{Leb128Iterator, Leb128Vec},
    BlobHash,
};

use crate::{backend::MAX_TOKEN_LENGTH, BlobClass, Deserialize, Serialize, Value};

use self::assert::AssertValue;

pub mod assert;
pub mod batch;
pub mod blob;
pub mod hash;
pub mod key;
pub mod log;
pub mod purge;

pub trait SerializeWithId: Send + Sync {
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>>;
}

pub trait ResolveId {
    fn resolve_id(&self, ids: Option<&AssignedIds>) -> u32;
}

pub enum MaybeDynamicValue {
    Static(Vec<u8>),
    Dynamic(Box<dyn SerializeWithId>),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum MaybeDynamicId {
    Static(u32),
    Dynamic(usize),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DynamicDocumentId(pub usize);

#[derive(Debug, Default)]
pub struct AssignedIds {
    pub document_ids: Vec<u32>,
    pub counter_ids: Vec<i64>,
}

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
    ChangeId {
        change_id: u64,
    },
    AssertValue {
        class: ValueClass<MaybeDynamicId>,
        assert_value: AssertValue,
    },
    Value {
        class: ValueClass<MaybeDynamicId>,
        op: ValueOp,
    },
    Index {
        field: u8,
        key: Vec<u8>,
        set: bool,
    },
    Bitmap {
        class: BitmapClass<MaybeDynamicId>,
        set: bool,
    },
    Log {
        set: MaybeDynamicValue,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BitmapClass<T> {
    DocumentIds,
    Tag { field: u8, value: TagValue<T> },
    Text { field: u8, token: BitmapHash },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapHash {
    pub hash: [u8; 8],
    pub len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TagValue<T> {
    Id(T),
    Text(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ValueClass<T> {
    Property(u8),
    Acl(u32),
    Lookup(LookupClass),
    FtsIndex(BitmapHash),
    FtsQueue(FtsQueueClass),
    Directory(DirectoryClass<T>),
    Blob(BlobOp),
    Config(Vec<u8>),
    Queue(QueueClass),
    Report(ReportClass),
    Any(AnyClass),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct FtsQueueClass {
    pub seq: u64,
    pub hash: BlobHash,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyClass {
    pub subspace: u8,
    pub key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum LookupClass {
    Key(Vec<u8>),
    Counter(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DirectoryClass<T> {
    NameToId(Vec<u8>),
    EmailToId(Vec<u8>),
    MemberOf { principal_id: T, member_of: T },
    Members { principal_id: T, has_member: T },
    Domain(Vec<u8>),
    Principal(T),
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
    Set(MaybeDynamicValue),
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
    LinkId { hash: BlobHash, id: u64 },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyKey<T: AsRef<[u8]>> {
    pub subspace: u8,
    pub key: T,
}

impl From<u32> for TagValue<MaybeDynamicId> {
    fn from(value: u32) -> Self {
        TagValue::Id(MaybeDynamicId::Static(value))
    }
}

impl From<u32> for TagValue<u32> {
    fn from(value: u32) -> Self {
        TagValue::Id(value)
    }
}

impl<T> From<Vec<u8>> for TagValue<T> {
    fn from(value: Vec<u8>) -> Self {
        TagValue::Text(value)
    }
}

impl<T> From<String> for TagValue<T> {
    fn from(value: String) -> Self {
        TagValue::Text(value.into_bytes())
    }
}

impl From<u8> for TagValue<u32> {
    fn from(value: u8) -> Self {
        TagValue::Id(value as u32)
    }
}

impl From<u8> for TagValue<MaybeDynamicId> {
    fn from(value: u8) -> Self {
        TagValue::Id(MaybeDynamicId::Static(value as u32))
    }
}

impl<T> From<()> for TagValue<T> {
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
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for i64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(i64::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
        })?))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            trc::StoreEvent::DataCorruption.caused_by(trc::location!())
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
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(
                T::deserialize_from(&mut bytes)
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            );
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
                value: TagValue::Id(MaybeDynamicId::Static(*self)),
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
                value: TagValue::Id(MaybeDynamicId::Static(*self as u32)),
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
    fn deserialize(_bytes: &[u8]) -> trc::Result<Self> {
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
            op: set
                .map(|op| ValueOp::Set(op.into()))
                .unwrap_or(ValueOp::Clear),
        }
    }
}

#[inline(always)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl<T> AsRef<ValueClass<T>> for ValueClass<T> {
    fn as_ref(&self) -> &ValueClass<T> {
        self
    }
}

impl<T> AsRef<BitmapClass<T>> for BitmapClass<T> {
    fn as_ref(&self) -> &BitmapClass<T> {
        self
    }
}

impl<T> BitmapClass<T> {
    pub fn tag_id(property: impl Into<u8>, id: u32) -> Self
    where
        TagValue<T>: From<u32>,
    {
        BitmapClass::Tag {
            field: property.into(),
            value: id.into(),
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
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        lz4_flex::decompress_size_prepended(bytes)
            .map_err(|err| {
                trc::StoreEvent::DecompressError
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .and_then(|result| {
                bincode::deserialize(&result).map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .caused_by(trc::location!())
                        .reason(err)
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

impl AssignedIds {
    pub fn push_document_id(&mut self, id: u32) {
        self.document_ids.push(id);
    }

    pub fn push_counter_id(&mut self, id: i64) {
        self.counter_ids.push(id);
    }

    pub fn get_document_id(&self, idx: usize) -> trc::Result<u32> {
        self.document_ids.get(idx).copied().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No document ids were created")
        })
    }

    pub fn first_document_id(&self) -> trc::Result<u32> {
        self.get_document_id(0)
    }

    pub fn last_document_id(&self) -> trc::Result<u32> {
        self.document_ids.last().copied().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No document ids were created")
        })
    }

    pub fn last_counter_id(&self) -> trc::Result<i64> {
        self.counter_ids.last().copied().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No document ids were created")
        })
    }
}

impl From<String> for MaybeDynamicValue {
    fn from(value: String) -> Self {
        MaybeDynamicValue::Static(value.into_bytes())
    }
}

impl From<&[u8]> for MaybeDynamicValue {
    fn from(value: &[u8]) -> Self {
        MaybeDynamicValue::Static(value.to_vec())
    }
}

impl From<Vec<u8>> for MaybeDynamicValue {
    fn from(value: Vec<u8>) -> Self {
        MaybeDynamicValue::Static(value)
    }
}

impl MaybeDynamicValue {
    pub fn resolve(&self, ids: &AssignedIds) -> trc::Result<Cow<[u8]>> {
        match self {
            MaybeDynamicValue::Static(value) => Ok(Cow::Borrowed(value.as_slice())),
            MaybeDynamicValue::Dynamic(value) => value.serialize_with_id(ids).map(Cow::Owned),
        }
    }
}

impl MaybeDynamicId {
    pub fn resolve(&self, ids: &AssignedIds) -> trc::Result<u32> {
        match self {
            MaybeDynamicId::Static(id) => Ok(*id),
            MaybeDynamicId::Dynamic(idx) => ids.get_document_id(*idx),
        }
    }
}

impl ResolveId for u32 {
    fn resolve_id(&self, _: Option<&AssignedIds>) -> u32 {
        *self
    }
}

impl ResolveId for MaybeDynamicId {
    fn resolve_id(&self, ids: Option<&AssignedIds>) -> u32 {
        match self {
            MaybeDynamicId::Static(id) => *id,
            MaybeDynamicId::Dynamic(idx) => ids
                .and_then(|ids| ids.document_ids.get(*idx))
                .copied()
                .unwrap_or(u32::MAX),
        }
    }
}

impl std::fmt::Debug for MaybeDynamicValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MaybeDynamicValue::Static(value) => write!(f, "{:?}", value),
            MaybeDynamicValue::Dynamic(_) => write!(f, "Dynamic"),
        }
    }
}

impl PartialEq for MaybeDynamicValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MaybeDynamicValue::Static(a), MaybeDynamicValue::Static(b)) => a == b,
            (MaybeDynamicValue::Dynamic(_), MaybeDynamicValue::Dynamic(_)) => true,
            _ => false,
        }
    }
}

impl Eq for MaybeDynamicValue {}

impl Hash for MaybeDynamicValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            MaybeDynamicValue::Static(value) => value.hash(state),
            MaybeDynamicValue::Dynamic(_) => 0.hash(state),
        }
    }
}

impl From<MaybeDynamicId> for MaybeDynamicValue {
    fn from(value: MaybeDynamicId) -> Self {
        match value {
            MaybeDynamicId::Static(id) => MaybeDynamicValue::Static(id.serialize()),
            MaybeDynamicId::Dynamic(idx) => {
                MaybeDynamicValue::Dynamic(Box::new(DynamicDocumentId(idx)))
            }
        }
    }
}

impl SerializeWithId for DynamicDocumentId {
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>> {
        ids.get_document_id(self.0).map(|id| id.serialize())
    }
}

pub(crate) trait RandomAvailableId {
    fn random_available_id(&self) -> u32;
}

impl RandomAvailableId for RoaringBitmap {
    fn random_available_id(&self) -> u32 {
        let mut last_id = 0;
        let mut available_ids = Vec::with_capacity(100);
        for id in self.iter() {
            for i in last_id..id {
                available_ids.push(i);
            }
            last_id = id + 1;
        }

        while available_ids.len() < 100 {
            available_ids.push(last_id);
            last_id += 1;
        }

        available_ids[rand::thread_rng().gen_range(0..available_ids.len())]
    }
}
