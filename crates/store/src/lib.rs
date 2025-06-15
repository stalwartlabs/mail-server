/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, sync::Arc};

pub mod backend;
pub mod config;
pub mod dispatch;
pub mod fts;
pub mod query;
pub mod write;

pub use ahash;
pub use blake3;
pub use parking_lot;
pub use rand;
pub use rkyv;
pub use roaring;
pub use xxhash_rust;

use ahash::AHashMap;
use backend::{fs::FsStore, http::HttpStore, memory::StaticMemoryStore};
use utils::config::cron::SimpleCron;
use write::{BitmapClass, ValueClass};

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self>;
    fn deserialize_owned(bytes: Vec<u8>) -> trc::Result<Self> {
        Self::deserialize(&bytes)
    }
}

pub trait Serialize {
    fn serialize(&self) -> trc::Result<Vec<u8>>;
}

pub trait SerializeInfallible {
    fn serialize(&self) -> Vec<u8>;
}

// Key serialization flags
pub(crate) const WITH_SUBSPACE: u32 = 1;

pub trait Key: Sync + Send + Clone {
    fn serialize(&self, flags: u32) -> Vec<u8>;
    fn subspace(&self) -> u8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapKey<T: AsRef<BitmapClass>> {
    pub account_id: u32,
    pub collection: u8,
    pub class: T,
    pub document_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexKey<T: AsRef<[u8]>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub field: u8,
    pub key: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexKeyPrefix {
    pub account_id: u32,
    pub collection: u8,
    pub field: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueKey<T: AsRef<ValueClass>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub class: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogKey {
    pub account_id: u32,
    pub collection: u8,
    pub change_id: u64,
}

pub const U64_LEN: usize = std::mem::size_of::<u64>();
pub const U32_LEN: usize = std::mem::size_of::<u32>();
pub const U16_LEN: usize = std::mem::size_of::<u16>();

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlobClass {
    Reserved {
        account_id: u32,
        expires: u64,
    },
    Linked {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
}

impl Default for BlobClass {
    fn default() -> Self {
        BlobClass::Reserved {
            account_id: 0,
            expires: 0,
        }
    }
}

pub const SUBSPACE_ACL: u8 = b'a';
pub const SUBSPACE_BITMAP_ID: u8 = b'b';
pub const SUBSPACE_BITMAP_TAG: u8 = b'c';
pub const SUBSPACE_BITMAP_TEXT: u8 = b'v';
pub const SUBSPACE_DIRECTORY: u8 = b'd';
pub const SUBSPACE_TASK_QUEUE: u8 = b'f';
pub const SUBSPACE_INDEXES: u8 = b'i';
pub const SUBSPACE_BLOB_RESERVE: u8 = b'j';
pub const SUBSPACE_BLOB_LINK: u8 = b'k';
pub const SUBSPACE_BLOBS: u8 = b't';
pub const SUBSPACE_LOGS: u8 = b'l';
pub const SUBSPACE_COUNTER: u8 = b'n';
pub const SUBSPACE_IN_MEMORY_VALUE: u8 = b'm';
pub const SUBSPACE_IN_MEMORY_COUNTER: u8 = b'y';
pub const SUBSPACE_PROPERTY: u8 = b'p';
pub const SUBSPACE_SETTINGS: u8 = b's';
pub const SUBSPACE_QUEUE_MESSAGE: u8 = b'e';
pub const SUBSPACE_QUEUE_EVENT: u8 = b'q';
pub const SUBSPACE_QUOTA: u8 = b'u';
pub const SUBSPACE_REPORT_OUT: u8 = b'h';
pub const SUBSPACE_REPORT_IN: u8 = b'r';
pub const SUBSPACE_FTS_INDEX: u8 = b'g';
pub const SUBSPACE_TELEMETRY_SPAN: u8 = b'o';
pub const SUBSPACE_TELEMETRY_INDEX: u8 = b'w';
pub const SUBSPACE_TELEMETRY_METRIC: u8 = b'x';

pub const SUBSPACE_RESERVED_2: u8 = b'z';

#[derive(Clone)]
pub struct IterateParams<T: Key> {
    begin: T,
    end: T,
    first: bool,
    ascending: bool,
    values: bool,
}

#[derive(Clone, Default)]
pub struct Stores {
    pub stores: AHashMap<String, Store>,
    pub blob_stores: AHashMap<String, BlobStore>,
    pub fts_stores: AHashMap<String, FtsStore>,
    pub in_memory_stores: AHashMap<String, InMemoryStore>,
    pub pubsub_stores: AHashMap<String, PubSubStore>,
    pub purge_schedules: Vec<PurgeSchedule>,
}

#[derive(Clone, Default)]
pub enum Store {
    #[cfg(feature = "sqlite")]
    SQLite(Arc<backend::sqlite::SqliteStore>),
    #[cfg(feature = "foundation")]
    FoundationDb(Arc<backend::foundationdb::FdbStore>),
    #[cfg(feature = "postgres")]
    PostgreSQL(Arc<backend::postgres::PostgresStore>),
    #[cfg(feature = "mysql")]
    MySQL(Arc<backend::mysql::MysqlStore>),
    #[cfg(feature = "rocks")]
    RocksDb(Arc<backend::rocksdb::RocksDbStore>),
    #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
    SQLReadReplica(Arc<backend::composite::read_replica::SQLReadReplica>),
    #[default]
    None,
}

#[derive(Clone)]
pub struct BlobStore {
    pub backend: BlobBackend,
    pub compression: CompressionAlgo,
}

#[derive(Clone, Copy, Debug)]
pub enum CompressionAlgo {
    None,
    Lz4,
}

#[derive(Clone)]
pub enum BlobBackend {
    Store(Store),
    Fs(Arc<FsStore>),
    #[cfg(feature = "s3")]
    S3(Arc<backend::s3::S3Store>),
    #[cfg(feature = "azure")]
    Azure(Arc<backend::azure::AzureStore>),
    #[cfg(feature = "enterprise")]
    Sharded(Arc<backend::composite::sharded_blob::ShardedBlob>),
}

#[derive(Clone)]
pub enum FtsStore {
    Store(Store),
    #[cfg(feature = "elastic")]
    ElasticSearch(Arc<backend::elastic::ElasticSearchStore>),
}

#[derive(Clone, Debug)]
pub enum InMemoryStore {
    Store(Store),
    #[cfg(feature = "redis")]
    Redis(Arc<backend::redis::RedisStore>),
    Http(Arc<HttpStore>),
    Static(Arc<StaticMemoryStore>),
    #[cfg(feature = "enterprise")]
    Sharded(Arc<backend::composite::sharded_lookup::ShardedInMemory>),
}

#[derive(Clone, Default)]
pub enum PubSubStore {
    #[cfg(feature = "redis")]
    Redis(Arc<backend::redis::RedisStore>),
    #[cfg(feature = "nats")]
    Nats(Arc<backend::nats::NatsPubSub>),
    #[cfg(feature = "zenoh")]
    Zenoh(Arc<backend::zenoh::ZenohPubSub>),
    #[cfg(feature = "kafka")]
    Kafka(Arc<backend::kafka::KafkaPubSub>),
    #[default]
    None,
}

#[cfg(feature = "sqlite")]
impl From<backend::sqlite::SqliteStore> for Store {
    fn from(store: backend::sqlite::SqliteStore) -> Self {
        Self::SQLite(Arc::new(store))
    }
}

#[cfg(feature = "foundation")]
impl From<backend::foundationdb::FdbStore> for Store {
    fn from(store: backend::foundationdb::FdbStore) -> Self {
        Self::FoundationDb(Arc::new(store))
    }
}

#[cfg(feature = "postgres")]
impl From<backend::postgres::PostgresStore> for Store {
    fn from(store: backend::postgres::PostgresStore) -> Self {
        Self::PostgreSQL(Arc::new(store))
    }
}

#[cfg(feature = "mysql")]
impl From<backend::mysql::MysqlStore> for Store {
    fn from(store: backend::mysql::MysqlStore) -> Self {
        Self::MySQL(Arc::new(store))
    }
}

#[cfg(feature = "rocks")]
impl From<backend::rocksdb::RocksDbStore> for Store {
    fn from(store: backend::rocksdb::RocksDbStore) -> Self {
        Self::RocksDb(Arc::new(store))
    }
}

impl From<FsStore> for BlobStore {
    fn from(store: FsStore) -> Self {
        BlobStore {
            backend: BlobBackend::Fs(Arc::new(store)),
            compression: CompressionAlgo::None,
        }
    }
}

#[cfg(feature = "s3")]
impl From<backend::s3::S3Store> for BlobStore {
    fn from(store: backend::s3::S3Store) -> Self {
        BlobStore {
            backend: BlobBackend::S3(Arc::new(store)),
            compression: CompressionAlgo::None,
        }
    }
}

#[cfg(feature = "azure")]
impl From<backend::azure::AzureStore> for BlobStore {
    fn from(store: backend::azure::AzureStore) -> Self {
        BlobStore {
            backend: BlobBackend::Azure(Arc::new(store)),
            compression: CompressionAlgo::None,
        }
    }
}

#[cfg(feature = "elastic")]
impl From<backend::elastic::ElasticSearchStore> for FtsStore {
    fn from(store: backend::elastic::ElasticSearchStore) -> Self {
        Self::ElasticSearch(Arc::new(store))
    }
}

#[cfg(feature = "redis")]
impl From<backend::redis::RedisStore> for InMemoryStore {
    fn from(store: backend::redis::RedisStore) -> Self {
        Self::Redis(Arc::new(store))
    }
}

impl From<Store> for FtsStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl From<Store> for BlobStore {
    fn from(store: Store) -> Self {
        BlobStore {
            backend: BlobBackend::Store(store),
            compression: CompressionAlgo::None,
        }
    }
}

impl From<Store> for InMemoryStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl Default for BlobStore {
    fn default() -> Self {
        Self {
            backend: BlobBackend::Store(Store::None),
            compression: CompressionAlgo::None,
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::Store(Store::None)
    }
}

impl Default for FtsStore {
    fn default() -> Self {
        Self::Store(Store::None)
    }
}

#[derive(Clone)]
pub enum PurgeStore {
    Data(Store),
    Blobs { store: Store, blob_store: BlobStore },
    Lookup(InMemoryStore),
}

#[derive(Clone)]
pub struct PurgeSchedule {
    pub cron: SimpleCron,
    pub store_id: String,
    pub store: PurgeStore,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value<'x> {
    Integer(i64),
    Bool(bool),
    Float(f64),
    Text(Cow<'x, str>),
    Blob(Cow<'x, [u8]>),
    Null,
}

impl Eq for Value<'_> {}

impl<'x> Value<'x> {
    pub fn to_str<'y: 'x>(&'y self) -> Cow<'x, str> {
        match self {
            Value::Text(s) => s.as_ref().into(),
            Value::Integer(i) => Cow::Owned(i.to_string()),
            Value::Bool(b) => Cow::Owned(b.to_string()),
            Value::Float(f) => Cow::Owned(f.to_string()),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()),
            Value::Null => Cow::Borrowed(""),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub values: Vec<Value<'static>>,
}

#[derive(Clone, Debug)]
pub struct Rows {
    pub rows: Vec<Row>,
}

#[derive(Clone, Debug)]
pub struct NamedRows {
    pub names: Vec<String>,
    pub rows: Vec<Row>,
}

#[derive(Clone, Copy)]
pub enum QueryType {
    Execute,
    Exists,
    QueryAll,
    QueryOne,
}

pub trait QueryResult: Sync + Send + 'static {
    fn from_exec(items: usize) -> Self;
    fn from_exists(exists: bool) -> Self;
    fn from_query_one(items: impl IntoRows) -> Self;
    fn from_query_all(items: impl IntoRows) -> Self;

    fn query_type() -> QueryType;
}

pub trait IntoRows {
    fn into_row(self) -> Option<Row>;
    fn into_rows(self) -> Rows;
    fn into_named_rows(self) -> NamedRows;
}

impl QueryResult for Option<Row> {
    fn query_type() -> QueryType {
        QueryType::QueryOne
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(items: impl IntoRows) -> Self {
        items.into_row()
    }
}

impl QueryResult for Rows {
    fn query_type() -> QueryType {
        QueryType::QueryAll
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(items: impl IntoRows) -> Self {
        items.into_rows()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for NamedRows {
    fn query_type() -> QueryType {
        QueryType::QueryAll
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(items: impl IntoRows) -> Self {
        items.into_named_rows()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for bool {
    fn query_type() -> QueryType {
        QueryType::Exists
    }

    fn from_exec(_: usize) -> Self {
        unreachable!()
    }

    fn from_exists(exists: bool) -> Self {
        exists
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl QueryResult for usize {
    fn query_type() -> QueryType {
        QueryType::Execute
    }

    fn from_exec(items: usize) -> Self {
        items
    }

    fn from_exists(_: bool) -> Self {
        unreachable!()
    }

    fn from_query_all(_: impl IntoRows) -> Self {
        unreachable!()
    }

    fn from_query_one(_: impl IntoRows) -> Self {
        unreachable!()
    }
}

impl<'x> From<&'x str> for Value<'x> {
    fn from(value: &'x str) -> Self {
        Self::Text(value.into())
    }
}

impl From<String> for Value<'_> {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<&'x String> for Value<'x> {
    fn from(value: &'x String) -> Self {
        Self::Text(value.into())
    }
}

impl<'x> From<Cow<'x, str>> for Value<'x> {
    fn from(value: Cow<'x, str>) -> Self {
        Self::Text(value)
    }
}

impl From<bool> for Value<'_> {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for Value<'_> {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<Value<'static>> for i64 {
    fn from(value: Value<'static>) -> Self {
        if let Value::Integer(value) = value {
            value
        } else {
            0
        }
    }
}

impl From<u64> for Value<'_> {
    fn from(value: u64) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<u32> for Value<'_> {
    fn from(value: u32) -> Self {
        Self::Integer(value as i64)
    }
}

impl From<f64> for Value<'_> {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl<'x> From<&'x [u8]> for Value<'x> {
    fn from(value: &'x [u8]) -> Self {
        Self::Blob(value.into())
    }
}

impl From<Vec<u8>> for Value<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value.into())
    }
}

impl Value<'_> {
    pub fn into_string(self) -> String {
        match self {
            Value::Text(s) => s.into_owned(),
            Value::Integer(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()).into_owned(),
            Value::Null => "".into(),
        }
    }

    pub fn into_lower_string(self) -> String {
        match self {
            Value::Text(s) => s.as_ref().to_lowercase(),
            Value::Integer(i) => i.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Blob(b) => String::from_utf8_lossy(b.as_ref()).to_lowercase(),
            Value::Null => "".into(),
        }
    }
}

impl From<Row> for Vec<String> {
    fn from(value: Row) -> Self {
        value.values.into_iter().map(|v| v.into_string()).collect()
    }
}

impl From<Row> for Vec<u32> {
    fn from(value: Row) -> Self {
        value
            .values
            .into_iter()
            .filter_map(|v| {
                if let Value::Integer(v) = v {
                    Some(v as u32)
                } else {
                    None
                }
            })
            .collect()
    }
}

impl From<Rows> for Vec<String> {
    fn from(value: Rows) -> Self {
        value
            .rows
            .into_iter()
            .flat_map(|v| v.values.into_iter().map(|v| v.into_string()))
            .collect()
    }
}

impl From<Rows> for Vec<u32> {
    fn from(value: Rows) -> Self {
        value
            .rows
            .into_iter()
            .flat_map(|v| {
                v.values.into_iter().filter_map(|v| {
                    if let Value::Integer(v) = v {
                        Some(v as u32)
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

impl Store {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn is_sql(&self) -> bool {
        match self {
            #[cfg(feature = "sqlite")]
            Store::SQLite(_) => true,
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => true,
            #[cfg(feature = "mysql")]
            Store::MySQL(_) => true,
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Store::SQLReadReplica(_) => true,
            _ => false,
        }
    }

    pub fn is_pg_or_mysql(&self) -> bool {
        match self {
            #[cfg(feature = "sqlite")]
            Store::SQLite(_) => true,
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(_) => true,
            _ => false,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn is_enterprise_store(&self) -> bool {
        match self {
            #[cfg(any(feature = "postgres", feature = "mysql"))]
            Store::SQLReadReplica(_) => true,
            _ => false,
        }
    }

    #[cfg(not(feature = "enterprise"))]
    pub fn is_enterprise_store(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(_) => f.debug_tuple("SQLite").finish(),
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => f.debug_tuple("FoundationDb").finish(),
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => f.debug_tuple("PostgreSQL").finish(),
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => f.debug_tuple("MySQL").finish(),
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => f.debug_tuple("RocksDb").finish(),
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(_) => f.debug_tuple("SQLReadReplica").finish(),
            Self::None => f.debug_tuple("None").finish(),
        }
    }
}

impl From<Value<'_>> for trc::Value {
    fn from(value: Value) -> Self {
        match value {
            Value::Integer(v) => trc::Value::Int(v),
            Value::Bool(v) => trc::Value::Bool(v),
            Value::Float(v) => trc::Value::Float(v),
            Value::Text(v) => trc::Value::String(match v {
                Cow::Borrowed(v) => v.into(),
                Cow::Owned(v) => v.into(),
            }),
            Value::Blob(v) => trc::Value::Bytes(v.into_owned()),
            Value::Null => trc::Value::None,
        }
    }
}

impl From<Value<'static>> for () {
    fn from(_: Value<'static>) -> Self {
        unreachable!()
    }
}

impl Stores {
    pub fn disable_enterprise_only(&mut self) {
        #[cfg(feature = "enterprise")]
        {
            #[cfg(any(feature = "postgres", feature = "mysql"))]
            self.stores
                .retain(|_, store| !matches!(store, Store::SQLReadReplica(_)));
            self.blob_stores
                .retain(|_, store| !matches!(store.backend, BlobBackend::Sharded(_)));
        }
    }
}
