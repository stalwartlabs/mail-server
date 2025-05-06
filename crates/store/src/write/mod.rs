/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

use log::ChangeLogBuilder;
use nlp::tokenizers::word::WordTokenizer;
use rkyv::util::AlignedVec;
use utils::{
    BlobHash,
    map::{
        bitmap::{Bitmap, ShortId},
        vec_map::VecMap,
    },
};

use crate::{BlobClass, backend::MAX_TOKEN_LENGTH};

use self::assert::AssertValue;

pub mod assert;
pub mod batch;
pub mod bitpack;
pub mod blob;
pub mod hash;
pub mod key;
pub mod log;
pub mod serialize;

pub(crate) const ARCHIVE_ALIGNMENT: usize = 16;

#[derive(Debug, Clone)]
pub struct Archive<T> {
    pub inner: T,
    pub version: u8,
    pub hash: u32,
}

#[derive(Debug, Clone)]
pub enum AlignedBytes {
    Aligned(AlignedVec<ARCHIVE_ALIGNMENT>),
    Vec(Vec<u8>),
}

#[repr(transparent)]
pub struct Archiver<T>(pub T)
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >;

#[derive(Debug)]
pub struct LegacyBincode<T: serde::Serialize + serde::de::DeserializeOwned> {
    pub inner: T,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct DynamicDocumentId(pub usize);

#[derive(Debug, Default)]
pub struct AssignedIds {
    pub counter_ids: Vec<i64>,
    pub change_id: Option<u64>,
}

#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 10;
#[cfg(not(feature = "test_mode"))]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(10);

#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_ATTEMPTS: u32 = 1000;
#[cfg(feature = "test_mode")]
pub(crate) const MAX_COMMIT_TIME: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub struct Batch<'x> {
    pub(crate) ops: &'x [Operation],
}

#[derive(Debug)]
pub struct BatchBuilder {
    current_change_id: Option<u64>,
    current_account_id: Option<u32>,
    current_collection: Option<u8>,
    current_document_id: Option<u32>,
    changes: VecMap<u32, ChangeLogBuilder>,
    changed_collections: VecMap<u32, ChangedCollection>,
    has_assertions: bool,
    batch_size: usize,
    batch_ops: usize,
    commit_points: Vec<usize>,
    ops: Vec<Operation>,
}

#[derive(Debug, Default)]
pub struct ChangedCollection {
    pub change_id: u64,
    pub changed_containers: Bitmap<ShortId>,
    pub changed_items: Bitmap<ShortId>,
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
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum ValueClass {
    Property(u8),
    Acl(u32),
    InMemory(InMemoryClass),
    FtsIndex(BitmapHash),
    TaskQueue(TaskQueueClass),
    Directory(DirectoryClass),
    Blob(BlobOp),
    Config(Vec<u8>),
    Queue(QueueClass),
    Report(ReportClass),
    Telemetry(TelemetryClass),
    Any(AnyClass),
    DocumentId,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum TaskQueueClass {
    IndexEmail {
        seq: u64,
        hash: BlobHash,
    },
    BayesTrain {
        seq: u64,
        hash: BlobHash,
        learn_spam: bool,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AnyClass {
    pub subspace: u8,
    pub key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum InMemoryClass {
    Key(Vec<u8>),
    Counter(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum DirectoryClass {
    NameToId(Vec<u8>),
    EmailToId(Vec<u8>),
    Index { word: Vec<u8>, principal_id: u32 },
    MemberOf { principal_id: u32, member_of: u32 },
    Members { principal_id: u32, has_member: u32 },
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
pub enum TelemetryClass {
    Span {
        span_id: u64,
    },
    Metric {
        timestamp: u64,
        metric_id: u64,
        node_id: u64,
    },
    Index {
        span_id: u64,
        value: Vec<u8>,
    },
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
    LinkId { hash: BlobHash, id: u64 },
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
        TagValue::Id(value as u32)
    }
}

impl From<()> for TagValue {
    fn from(_: ()) -> Self {
        TagValue::Text(vec![])
    }
}

pub trait TokenizeText {
    fn tokenize_into(&self, tokens: &mut HashSet<String>);
    fn to_tokens(&self) -> HashSet<String>;
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

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()>;
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
    pub fn tag_id(property: impl Into<u8>, id: u32) -> Self
    where
        TagValue: From<u32>,
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

impl AssignedIds {
    pub fn push_counter_id(&mut self, id: i64) {
        self.counter_ids.push(id);
    }

    pub fn change_id(&self) -> trc::Result<u64> {
        self.change_id.ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No change id was assigned")
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

impl QueueClass {
    pub fn due(&self) -> Option<u64> {
        match self {
            QueueClass::DmarcReportHeader(report_event) => report_event.due.into(),
            QueueClass::TlsReportHeader(report_event) => report_event.due.into(),
            _ => None,
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Archive<T> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl TagValue {
    pub fn serialized_size(&self) -> usize {
        match self {
            TagValue::Id(_) => std::mem::size_of::<u32>(),
            TagValue::Text(items) => items.len(),
        }
    }
}
