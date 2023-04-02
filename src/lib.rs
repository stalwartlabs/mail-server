use std::fmt::Display;

pub mod backend;
pub mod fts;
pub mod query;
pub mod write;

#[cfg(test)]
pub mod tests;

#[cfg(feature = "rocks")]
pub struct Store {
    db: rocksdb::OptimisticTransactionDB<rocksdb::MultiThreaded>,
}

#[cfg(feature = "foundation")]
#[allow(dead_code)]
pub struct Store {
    db: foundationdb::Database,
    guard: foundationdb::api::NetworkAutoStop,
}

#[cfg(feature = "foundation")]
pub struct ReadTransaction<'x> {
    db: &'x foundationdb::Database,
    pub trx: foundationdb::Transaction,
    trx_age: std::time::Instant,
}

#[cfg(feature = "sqlite")]
pub struct Store {
    conn_pool: r2d2::Pool<backend::sqlite::pool::SqliteConnectionManager>,
    worker_pool: rayon::ThreadPool,
}

#[cfg(feature = "sqlite")]
pub struct ReadTransaction<'x> {
    conn: r2d2::PooledConnection<backend::sqlite::pool::SqliteConnectionManager>,
    _p: std::marker::PhantomData<&'x ()>,
}

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self>;
}

pub trait Serialize {
    fn serialize(self) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapKey<T: AsRef<[u8]>> {
    pub account_id: u32,
    pub collection: u8,
    pub family: u8,
    pub field: u8,
    pub block_num: u32,
    pub key: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub struct ValueKey {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub family: u8,
    pub field: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobKey<T: AsRef<[u8]>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub hash: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AclKey {
    pub grant_account_id: u32,
    pub to_account_id: u32,
    pub to_collection: u8,
    pub to_document_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogKey {
    pub account_id: u32,
    pub collection: u8,
    pub change_id: u64,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    NotFound,
    InternalError(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotFound => write!(f, "not found"),
            Error::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

pub const BM_DOCUMENT_IDS: u8 = 0;
pub const BM_KEYWORD: u8 = 1 << 5;
pub const BM_TAG: u8 = 1 << 6;
pub const BM_HASH: u8 = 1 << 7;

pub const HASH_EXACT: u8 = 0;
pub const HASH_STEMMED: u8 = 1 << 6;

pub const BLOOM_BIGRAM: u8 = 1 << 0;
pub const BLOOM_TRIGRAM: u8 = 1 << 1;

pub const TAG_ID: u8 = 0;
pub const TAG_TEXT: u8 = 1 << 0;
pub const TAG_STATIC: u8 = 1 << 1;
