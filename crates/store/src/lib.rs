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

use std::{fmt::Display, sync::Arc};

pub mod backend;
pub mod dispatch;
pub mod fts;
pub mod query;
pub mod write;

pub use ahash;
use backend::{foundationdb::FdbStore, fs::FsStore, s3::S3Store, sqlite::SqliteStore};
pub use blake3;
pub use parking_lot;
pub use rand;
pub use roaring;
use write::{BitmapClass, BlobOp, ValueClass};

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
pub struct BlobKey<T: AsRef<BlobHash>> {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub hash: T,
    pub op: BlobOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogKey {
    pub account_id: u32,
    pub collection: u8,
    pub change_id: u64,
}

pub const BLOB_HASH_LEN: usize = 32;
pub const U64_LEN: usize = std::mem::size_of::<u64>();
pub const U32_LEN: usize = std::mem::size_of::<u32>();

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BlobHash([u8; BLOB_HASH_LEN]);

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlobClass {
    Reserved {
        account_id: u32,
    },
    Linked {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
}

impl Default for BlobClass {
    fn default() -> Self {
        BlobClass::Reserved { account_id: 0 }
    }
}

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
pub const SUBSPACE_BLOBS: u8 = b'o';
pub const SUBSPACE_BLOB_DATA: u8 = b't';
pub const SUBSPACE_ACLS: u8 = b'a';
pub const SUBSPACE_COUNTERS: u8 = b'c';

pub struct IterateParams<T: Key> {
    begin: T,
    end: T,
    first: bool,
    ascending: bool,
    values: bool,
}

#[derive(Clone)]
pub enum Store {
    SQLite(Arc<SqliteStore>),
    FoundationDb(Arc<FdbStore>),
}

#[derive(Clone)]
pub enum BlobStore {
    Fs(Arc<FsStore>),
    S3(Arc<S3Store>),
    Sqlite(Arc<SqliteStore>),
    FoundationDb(Arc<FdbStore>),
}

#[derive(Clone)]
pub enum FtsStore {
    Store(Store),
}

impl From<SqliteStore> for Store {
    fn from(store: SqliteStore) -> Self {
        Self::SQLite(Arc::new(store))
    }
}

impl From<FdbStore> for Store {
    fn from(store: FdbStore) -> Self {
        Self::FoundationDb(Arc::new(store))
    }
}

impl From<FsStore> for BlobStore {
    fn from(store: FsStore) -> Self {
        Self::Fs(Arc::new(store))
    }
}

impl From<S3Store> for BlobStore {
    fn from(store: S3Store) -> Self {
        Self::S3(Arc::new(store))
    }
}

impl From<Store> for FtsStore {
    fn from(store: Store) -> Self {
        Self::Store(store)
    }
}

impl From<Store> for BlobStore {
    fn from(store: Store) -> Self {
        match store {
            Store::SQLite(store) => Self::Sqlite(store),
            Store::FoundationDb(store) => Self::FoundationDb(store),
        }
    }
}
