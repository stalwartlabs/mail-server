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
    f32::consts::E,
    fmt::Display,
    ops::{BitAndAssign, Range},
};

use roaring::RoaringBitmap;

use crate::{
    fts::{index::FtsDocument, FtsFilter},
    write::{key::KeySerializer, Batch, BitmapClass, ValueClass},
    BitmapKey, BlobStore, Deserialize, Error, FtsStore, IterateParams, Key, LookupStore,
    QueryResult, Store, Value, ValueKey, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_INDEX_VALUES,
    SUBSPACE_LOGS, SUBSPACE_VALUES, U32_LEN,
};

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_value(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_value(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_value(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_value(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_value(key).await,
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
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_bitmap(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_bitmap(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_bitmap(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_bitmap(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_bitmap(key).await,
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

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate(params, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate(params, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate(params, cb).await,
        }
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_counter(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_counter(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_counter(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_counter(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_counter(key).await,
        }
    }

    pub async fn write(&self, batch: Batch) -> crate::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.write(batch).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.write(batch).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.write(batch).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.write(batch).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.write(batch).await,
        }
    }

    pub async fn purge_bitmaps(&self) -> crate::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.purge_bitmaps().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.purge_bitmaps().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.purge_bitmaps().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.purge_bitmaps().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.purge_bitmaps().await,
        }
    }
    pub(crate) async fn delete_range(
        &self,
        subspace: u8,
        from: &[u8],
        to: &[u8],
    ) -> crate::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_range(subspace, from, to).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_range(subspace, from, to).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_range(subspace, from, to).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_range(subspace, from, to).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_range(subspace, from, to).await,
        }
    }

    pub async fn purge_account(&self, account_id: u32) -> crate::Result<()> {
        let from_key = KeySerializer::new(U32_LEN).write(account_id).finalize();
        let to_key = KeySerializer::new(U32_LEN).write(account_id + 1).finalize();

        for subspace in [
            SUBSPACE_BITMAPS,
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_INDEXES,
            SUBSPACE_INDEX_VALUES,
        ] {
            self.delete_range(subspace, &from_key, &to_key).await?;
        }

        Ok(())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<u32>) -> crate::Result<Option<Vec<u8>>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_blob(key, range).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_blob(key, range).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_blob(key, range).await,
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.put_blob(key, data).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.put_blob(key, data).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.put_blob(key, data).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_blob(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_blob(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_blob(key).await,
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        use crate::{SUBSPACE_BLOBS, SUBSPACE_BLOB_DATA, SUBSPACE_COUNTERS};

        for subspace in [
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_BITMAPS,
            SUBSPACE_INDEXES,
            SUBSPACE_BLOBS,
            SUBSPACE_INDEX_VALUES,
            SUBSPACE_COUNTERS,
            SUBSPACE_BLOB_DATA,
        ] {
            self.delete_range(subspace, &[0u8], &[u8::MAX])
                .await
                .unwrap();
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn blob_hash_expire_all(&self) {
        use crate::{
            write::{key::DeserializeBigEndian, BatchBuilder, BlobOp, F_CLEAR},
            BlobHash, BlobKey, BLOB_HASH_LEN, U64_LEN,
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
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.assert_is_empty().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.assert_is_empty().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.assert_is_empty().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.assert_is_empty().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.assert_is_empty().await,
        }
    }
}

impl BlobStore {
    pub async fn get_blob(&self, key: &[u8], range: Range<u32>) -> crate::Result<Option<Vec<u8>>> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.get_blob(key, range).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.get_blob(key, range).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.get_blob(key, range).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.get_blob(key, range).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.get_blob(key, range).await,
            },
            Self::Fs(store) => store.get_blob(key, range).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.get_blob(key, range).await,
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.put_blob(key, data).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.put_blob(key, data).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.put_blob(key, data).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.put_blob(key, data).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.put_blob(key, data).await,
            },
            Self::Fs(store) => store.put_blob(key, data).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.put_blob(key, data).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.delete_blob(key).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.delete_blob(key).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.delete_blob(key).await,
            },
            Self::Fs(store) => store.delete_blob(key).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.delete_blob(key).await,
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
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => store.fts_index(document).await,
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
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => {
                store.fts_query(account_id, collection, filters).await
            }
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
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => {
                store.fts_remove(account_id, collection, document_id).await
            }
        }
    }

    pub async fn remove_all(&self, account_id: u32) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_remove_all(account_id).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => store.fts_remove_all(account_id).await,
        }
    }
}

impl LookupStore {
    pub async fn query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> crate::Result<T> {
        let todo = true;
        let result = match self {
            LookupStore::Store(store) => {
                match store {
                    Store::SQLite(store) => store.query(query, params).await,
                    //Store::FoundationDb(store) => store.query(query, params).await,
                    Store::PostgreSQL(store) => store.query(query, params).await,
                    Store::MySQL(store) => store.query(query, params).await,
                    //Store::RocksDb(store) => store.query(query, params).await,
                    _ => todo!(),
                }
            }
            LookupStore::Memory(store) => store.query(query, params),
        };

        tracing::trace!( context = "store", event = "query", query = query, result = ?result);

        result
    }
}
