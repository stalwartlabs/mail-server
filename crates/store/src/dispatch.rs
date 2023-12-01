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
    fmt::Display,
    ops::{BitAndAssign, Range},
};

use roaring::RoaringBitmap;

use crate::{
    fts::{index::FtsDocument, FtsFilter},
    query,
    write::{Batch, BitmapClass, ValueClass},
    BitmapKey, BlobStore, Deserialize, FtsStore, IterateParams, Key, Store, ValueKey,
};

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        match self {
            Self::SQLite(store) => store.get_value(key).await,
            Self::FoundationDb(store) => store.get_value(key).await,
            Self::PostgreSQL(store) => store.get_value(key).await,
            Self::MySQL(store) => store.get_value(key).await,
        }
    }

    pub async fn get_values<U>(&self, key: Vec<impl Key>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        let mut results = Vec::with_capacity(key.len());

        for key in key {
            results.push(self.get_value(key).await?);
        }

        Ok(results)
    }

    pub async fn get_bitmap(
        &self,
        key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        match self {
            Self::SQLite(store) => store.get_bitmap(key).await,
            Self::FoundationDb(store) => store.get_bitmap(key).await,
            Self::PostgreSQL(store) => store.get_bitmap(key).await,
            Self::MySQL(store) => store.get_bitmap(key).await,
        }
    }

    pub async fn get_bitmaps_intersection(
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

    pub async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        value: &[u8],
        op: query::Operator,
    ) -> crate::Result<Option<RoaringBitmap>> {
        match self {
            Self::SQLite(store) => {
                store
                    .range_to_bitmap(account_id, collection, field, value, op)
                    .await
            }
            Self::FoundationDb(store) => {
                store
                    .range_to_bitmap(account_id, collection, field, value, op)
                    .await
            }
            Self::PostgreSQL(store) => {
                store
                    .range_to_bitmap(account_id, collection, field, value, op)
                    .await
            }
            Self::MySQL(store) => {
                store
                    .range_to_bitmap(account_id, collection, field, value, op)
                    .await
            }
        }
    }

    pub async fn sort_index(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        field: impl Into<u8> + Sync + Send,
        ascending: bool,
        cb: impl for<'x> FnMut(&'x [u8], u32) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => {
                store
                    .sort_index(account_id, collection, field, ascending, cb)
                    .await
            }
            Self::FoundationDb(store) => {
                store
                    .sort_index(account_id, collection, field, ascending, cb)
                    .await
            }
            Self::PostgreSQL(store) => {
                store
                    .sort_index(account_id, collection, field, ascending, cb)
                    .await
            }
            Self::MySQL(store) => {
                store
                    .sort_index(account_id, collection, field, ascending, cb)
                    .await
            }
        }
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => store.iterate(params, cb).await,
            Self::FoundationDb(store) => store.iterate(params, cb).await,
            Self::PostgreSQL(store) => store.iterate(params, cb).await,
            Self::MySQL(store) => store.iterate(params, cb).await,
        }
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        match self {
            Self::SQLite(store) => store.get_counter(key).await,
            Self::FoundationDb(store) => store.get_counter(key).await,
            Self::PostgreSQL(store) => store.get_counter(key).await,
            Self::MySQL(store) => store.get_counter(key).await,
        }
    }

    pub async fn write(&self, batch: Batch) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => store.write(batch).await,
            Self::FoundationDb(store) => store.write(batch).await,
            Self::PostgreSQL(store) => store.write(batch).await,
            Self::MySQL(store) => store.write(batch).await,
        }
    }

    pub async fn purge_bitmaps(&self) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => store.purge_bitmaps().await,
            Self::FoundationDb(store) => store.purge_bitmaps().await,
            Self::PostgreSQL(store) => store.purge_bitmaps().await,
            Self::MySQL(store) => store.purge_bitmaps().await,
        }
    }
    pub async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => store.purge_account(account_id).await,
            Self::FoundationDb(store) => store.purge_account(account_id).await,
            Self::PostgreSQL(store) => store.purge_account(account_id).await,
            Self::MySQL(store) => store.purge_account(account_id).await,
        }
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<u32>) -> crate::Result<Option<Vec<u8>>> {
        match self {
            Self::SQLite(store) => store.get_blob(key, range).await,
            Self::FoundationDb(store) => store.get_blob(key, range).await,
            Self::PostgreSQL(store) => store.get_blob(key, range).await,
            Self::MySQL(store) => store.get_blob(key, range).await,
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self {
            Self::SQLite(store) => store.put_blob(key, data).await,
            Self::FoundationDb(store) => store.put_blob(key, data).await,
            Self::PostgreSQL(store) => store.put_blob(key, data).await,
            Self::MySQL(store) => store.put_blob(key, data).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match self {
            Self::SQLite(store) => store.delete_blob(key).await,
            Self::FoundationDb(store) => store.delete_blob(key).await,
            Self::PostgreSQL(store) => store.delete_blob(key).await,
            Self::MySQL(store) => store.delete_blob(key).await,
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        match self {
            Self::SQLite(store) => store.destroy().await,
            Self::FoundationDb(store) => store.destroy().await,
            Self::PostgreSQL(store) => store.destroy().await,
            Self::MySQL(store) => store.destroy().await,
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn blob_hash_expire_all(&self) {
        use crate::{
            write::{key::DeserializeBigEndian, BatchBuilder, BlobOp, F_CLEAR},
            BlobHash, BlobKey, BLOB_HASH_LEN, U32_LEN, U64_LEN,
        };

        // Delete all temporary hashes
        let from_key = BlobKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            op: BlobOp::Reserve { until: 0, size: 0 },
            hash: BlobHash::default(),
        };
        let to_key = BlobKey {
            account_id: u32::MAX,
            collection: 0,
            document_id: 0,
            op: BlobOp::Reserve { until: 0, size: 0 },
            hash: BlobHash::default(),
        };
        let mut batch = BatchBuilder::new();
        let mut last_account_id = u32::MAX;
        self.iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let account_id = key.deserialize_be_u32(1)?;
                if account_id != last_account_id {
                    last_account_id = account_id;
                    batch.with_account_id(account_id);
                }

                batch.blob(
                    BlobHash::try_from_hash_slice(
                        key.get(1 + U32_LEN..1 + U32_LEN + BLOB_HASH_LEN).unwrap(),
                    )
                    .unwrap(),
                    BlobOp::Reserve {
                        until: key.deserialize_be_u64(key.len() - (U64_LEN + U32_LEN))?,
                        size: key.deserialize_be_u32(key.len() - U32_LEN)? as usize,
                    },
                    F_CLEAR,
                );

                Ok(true)
            },
        )
        .await
        .unwrap();
        self.write(batch.build()).await.unwrap();
    }

    #[cfg(feature = "test_mode")]
    pub async fn assert_is_empty(&self, blob_store: crate::BlobStore) {
        self.blob_hash_expire_all().await;
        self.blob_hash_purge(blob_store).await.unwrap();
        self.purge_bitmaps().await.unwrap();

        match self {
            Self::SQLite(store) => store.assert_is_empty().await,
            Self::FoundationDb(store) => store.assert_is_empty().await,
            Self::PostgreSQL(store) => store.assert_is_empty().await,
            Self::MySQL(store) => store.assert_is_empty().await,
        }
    }
}

impl BlobStore {
    pub async fn get_blob(&self, key: &[u8], range: Range<u32>) -> crate::Result<Option<Vec<u8>>> {
        match self {
            Self::Fs(store) => store.get_blob(key, range).await,
            Self::S3(store) => store.get_blob(key, range).await,
            Self::Sqlite(store) => store.get_blob(key, range).await,
            Self::FoundationDb(store) => store.get_blob(key, range).await,
            Self::PostgreSQL(store) => store.get_blob(key, range).await,
            Self::MySQL(store) => store.get_blob(key, range).await,
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self {
            Self::Fs(store) => store.put_blob(key, data).await,
            Self::S3(store) => store.put_blob(key, data).await,
            Self::Sqlite(store) => store.put_blob(key, data).await,
            Self::FoundationDb(store) => store.put_blob(key, data).await,
            Self::PostgreSQL(store) => store.put_blob(key, data).await,
            Self::MySQL(store) => store.put_blob(key, data).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match self {
            Self::Fs(store) => store.delete_blob(key).await,
            Self::S3(store) => store.delete_blob(key).await,
            Self::Sqlite(store) => store.delete_blob(key).await,
            Self::FoundationDb(store) => store.delete_blob(key).await,
            Self::PostgreSQL(store) => store.delete_blob(key).await,
            Self::MySQL(store) => store.delete_blob(key).await,
        }
    }
}

impl FtsStore {
    pub async fn index<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        document: FtsDocument<'_, T>,
    ) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_index(document).await,
        }
    }

    pub async fn query<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<FtsFilter<T>>,
    ) -> crate::Result<RoaringBitmap> {
        match self {
            FtsStore::Store(store) => store.fts_query(account_id, collection, filters).await,
        }
    }

    pub async fn remove(
        &self,
        account_id: u32,
        collection: u8,
        document_id: u32,
    ) -> crate::Result<bool> {
        match self {
            FtsStore::Store(store) => store.fts_remove(account_id, collection, document_id).await,
        }
    }

    pub async fn remove_all(&self, account_id: u32) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_remove_all(account_id).await,
        }
    }
}
