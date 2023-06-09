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

use std::fmt::Display;

use blob::BlobStore;

pub mod backend;
pub mod blob;
pub mod fts;
pub mod query;
pub mod write;

pub use ahash;
pub use blake3;
pub use parking_lot;
pub use rand;
pub use roaring;

#[cfg(feature = "rocks")]
pub struct Store {
    db: rocksdb::OptimisticTransactionDB<rocksdb::MultiThreaded>,
}

#[cfg(feature = "foundation")]
#[allow(dead_code)]
pub struct Store {
    db: foundationdb::Database,
    guard: foundationdb::api::NetworkAutoStop,
    blob: BlobStore,
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
    id_assigner: std::sync::Arc<
        parking_lot::Mutex<
            lru_cache::LruCache<
                backend::sqlite::id_assign::IdCacheKey,
                backend::sqlite::id_assign::IdAssigner,
            >,
        >,
    >,
    worker_pool: rayon::ThreadPool,
    blob: BlobStore,
}

#[cfg(feature = "sqlite")]
pub struct ReadTransaction<'x> {
    conn: r2d2::PooledConnection<backend::sqlite::pool::SqliteConnectionManager>,
    _p: std::marker::PhantomData<&'x ()>,
}

#[cfg(not(feature = "backend"))]
#[allow(dead_code)]
pub struct Store {
    blob: BlobStore,
}

#[cfg(not(feature = "backend"))]
pub struct ReadTransaction<'x> {
    _db: &'x [u8],
}

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self>;
}

pub trait Serialize {
    fn serialize(self) -> Vec<u8>;
}

pub trait Key: Serialize + Sync + Send + 'static {
    fn subspace(&self) -> u8;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlobKind {
    Linked {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
    LinkedMaildir {
        account_id: u32,
        document_id: u32,
    },
    Temporary {
        account_id: u32,
        timestamp: u64,
        seq: u32,
    },
}

impl BlobKind {
    pub fn is_document(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
    ) -> bool {
        matches!(self, BlobKind::Linked {
            account_id: a,
            collection: c,
            document_id: d,
        } if *a == account_id && *c == collection.into() && *d == document_id)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    AssertValueFailed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InternalError(msg) => write!(f, "Internal Error: {}", msg),
            Error::AssertValueFailed => write!(f, "Transaction failed: Hash mismatch"),
        }
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::InternalError(msg)
    }
}

pub const BM_DOCUMENT_IDS: u8 = 0;
pub const BM_TAG: u8 = 1 << 5;
pub const BM_HASH: u8 = 1 << 6;

pub const HASH_EXACT: u8 = 0;
pub const HASH_STEMMED: u8 = 1 << 6;

pub const BLOOM_BIGRAM: u8 = 1 << 0;
pub const BLOOM_TRIGRAM: u8 = 1 << 1;

pub const TAG_ID: u8 = 0;
pub const TAG_TEXT: u8 = 1 << 0;
pub const TAG_STATIC: u8 = 1 << 1;

pub const SUBSPACE_BITMAPS: u8 = b'b';
pub const SUBSPACE_VALUES: u8 = b'v';
pub const SUBSPACE_LOGS: u8 = b'l';
pub const SUBSPACE_INDEXES: u8 = b'i';
pub const SUBSPACE_QUOTAS: u8 = b'q';

#[cfg(not(feature = "backend"))]
impl Store {
    pub async fn open(_config: &utils::config::Config) -> crate::Result<Self> {
        unimplemented!("No backend selected")
    }

    pub async fn purge_bitmaps(&self) -> crate::Result<()> {
        unimplemented!("No backend selected")
    }

    pub async fn purge_account(&self, _account_id: u32) -> crate::Result<()> {
        unimplemented!("No backend selected")
    }

    pub async fn read_transaction(&self) -> crate::Result<ReadTransaction<'_>> {
        unimplemented!("No backend selected")
    }

    pub async fn write(&self, _batch: write::Batch) -> crate::Result<()> {
        unimplemented!("No backend selected")
    }

    pub async fn assign_document_id(
        &self,
        _account_id: u32,
        _collection: impl Into<u8>,
    ) -> crate::Result<u32> {
        unimplemented!("No backend selected")
    }

    pub async fn assign_change_id(&self, _account_id: u32) -> crate::Result<u64> {
        unimplemented!("No backend selected")
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        unimplemented!("No backend selected")
    }

    #[cfg(feature = "test_mode")]
    pub async fn assert_is_empty(&self) {
        unimplemented!("No backend selected")
    }
}

#[cfg(not(feature = "backend"))]
impl ReadTransaction<'_> {
    pub async fn get_value<U>(&self, _key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        unimplemented!("No backend selected")
    }

    pub async fn get_bitmap<T: AsRef<[u8]>>(
        &self,
        _key: BitmapKey<T>,
    ) -> crate::Result<Option<roaring::RoaringBitmap>> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn get_bitmaps_intersection<T: AsRef<[u8]>>(
        &self,
        _keys: Vec<BitmapKey<T>>,
    ) -> crate::Result<Option<roaring::RoaringBitmap>> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn get_bitmaps_union<T: AsRef<[u8]>>(
        &self,
        _keys: Vec<BitmapKey<T>>,
    ) -> crate::Result<Option<roaring::RoaringBitmap>> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn range_to_bitmap(
        &self,
        _account_id: u32,
        _collection: u8,
        _field: u8,
        _value: Vec<u8>,
        _op: query::Operator,
    ) -> crate::Result<Option<roaring::RoaringBitmap>> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn sort_index(
        &self,
        _account_id: u32,
        _collection: u8,
        _field: u8,
        _ascending: bool,
        _cb: impl FnMut(&[u8], u32) -> bool,
    ) -> crate::Result<()> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn iterate<T>(
        &self,
        _acc: T,
        _begin: impl Key,
        _end: impl Key,
        _first: bool,
        _ascending: bool,
        _cb: impl Fn(&mut T, &[u8], &[u8]) -> crate::Result<bool> + Sync + Send + 'static,
    ) -> crate::Result<T> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn get_last_change_id(
        &self,
        _account_id: u32,
        _collection: u8,
    ) -> crate::Result<Option<u64>> {
        unimplemented!("No backend selected")
    }

    pub(crate) async fn get_quota(&self, _account_id: u32) -> crate::Result<i64> {
        unimplemented!("No backend selected")
    }

    pub async fn refresh_if_old(&mut self) -> crate::Result<()> {
        unimplemented!("No backend selected")
    }
}
