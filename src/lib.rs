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
    #[cfg(feature = "foundation")]
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

pub const BM_DOCUMENT_IDS: u8 = 0;
pub const BM_TERM: u8 = 0x10;
pub const BM_TAG: u8 = 0x20;
pub const BM_BLOOM: u8 = 0x40;

pub const BLOOM_UNIGRAM: u8 = 0x00;
pub const BLOOM_BIGRAM: u8 = 0x01;
pub const BLOOM_TRIGRAM: u8 = 0x02;

pub const TERM_EXACT: u8 = 0x00;
pub const TERM_STEMMED: u8 = 0x01;
pub const TERM_STRING: u8 = 0x02;
pub const TERM_HASH: u8 = 0x04;

pub const TAG_ID: u8 = 0x00;
pub const TAG_TEXT: u8 = 0x01;
pub const TAG_STATIC: u8 = 0x02;
