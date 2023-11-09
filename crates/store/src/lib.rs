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

use std::{fmt::Display, ops::BitAndAssign};

pub mod backend;
pub mod blob;
//pub mod fts;
pub mod query;
pub mod write;

pub use ahash;
pub use blake3;
pub use parking_lot;
use query::{filter::StoreQuery, log::StoreLog, sort::StoreSort};
pub use rand;
pub use roaring;
use roaring::RoaringBitmap;
use write::{Batch, BitmapClass, ValueClass};

#[cfg(feature = "rocks")]
pub struct Store {
    db: rocksdb::OptimisticTransactionDB<rocksdb::MultiThreaded>,
}

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self>;
}

pub trait Serialize {
    fn serialize(self) -> Vec<u8>;
}

pub trait Key: Sync + Send {
    fn serialize(&self, include_subspace: bool) -> Vec<u8>;
    fn subspace(&self) -> u8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapKey<T: AsRef<BitmapClass>> {
    pub account_id: u32,
    pub collection: u8,
    pub class: T,
    pub block_num: u32,
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

pub const SUBSPACE_BITMAPS: u8 = b'b';
pub const SUBSPACE_VALUES: u8 = b'v';
pub const SUBSPACE_LOGS: u8 = b'l';
pub const SUBSPACE_INDEXES: u8 = b'i';
pub const SUBSPACE_QUOTAS: u8 = b'q';

#[async_trait::async_trait]
pub trait StoreInit: Sized {
    async fn open(config: &utils::config::Config) -> crate::Result<Self>;
}

#[async_trait::async_trait]
pub trait StorePurge {
    async fn purge_bitmaps(&self) -> crate::Result<()>;
    async fn purge_account(&self, account_id: u32) -> crate::Result<()>;
}

#[async_trait::async_trait]
pub trait StoreId {
    async fn assign_change_id(&self, account_id: u32) -> crate::Result<u64>;
    async fn assign_document_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<u32>;
}

#[async_trait::async_trait]
pub trait StoreRead: Sync {
    async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static;

    async fn get_values<U>(&self, key: Vec<impl Key>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        let mut results = Vec::with_capacity(key.len());

        for key in key {
            results.push(self.get_value(key).await?);
        }

        Ok(results)
    }

    async fn get_bitmap(&self, key: BitmapKey<BitmapClass>)
        -> crate::Result<Option<RoaringBitmap>>;

    async fn get_bitmaps_intersection(
        &self,
        keys: Vec<BitmapKey<BitmapClass>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut result: Option<RoaringBitmap> = None;
        for key in keys {
            if let Some(bitmap) = self.get_bitmap(key).await? {
                if let Some(result) = &mut result {
                    result.bitand_assign(&bitmap);
                    if result.is_empty() {
                        break;
                    }
                } else {
                    result = Some(bitmap);
                }
            } else {
                return Ok(None);
            }
        }
        Ok(result)
    }

    async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        value: Vec<u8>,
        op: query::Operator,
    ) -> crate::Result<Option<RoaringBitmap>>;

    async fn sort_index(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        field: impl Into<u8> + Sync + Send,
        ascending: bool,
        cb: impl for<'x> FnMut(&'x [u8], u32) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()>;

    async fn iterate(
        &self,
        begin: impl Key,
        end: impl Key,
        first: bool,
        ascending: bool,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()>;

    async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<Option<u64>>;

    async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64>;

    #[cfg(feature = "test_mode")]
    async fn assert_is_empty(&self);
}

#[async_trait::async_trait]
pub trait StoreWrite {
    async fn write(&self, batch: Batch) -> crate::Result<()>;
    /*async fn set_value(
        &self,
        key: impl Key,
        value: impl Serialize + Sync + Send + 'static,
    ) -> crate::Result<()>;*/
    #[cfg(feature = "test_mode")]
    async fn destroy(&self);
}

pub trait Store:
    StoreInit
    + StoreRead
    + StoreWrite
    + StoreId
    + StorePurge
    + StoreQuery
    + StoreSort
    + StoreLog
    + Sync
    + Send
    + 'static
{
}
