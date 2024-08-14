/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    ops::{BitAndAssign, Range},
    time::Instant,
};

use roaring::RoaringBitmap;
use trc::{AddContext, StoreEvent};

use crate::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, AnyClass, AnyKey, AssignedIds, Batch, BatchBuilder, BitmapClass, BitmapHash,
        Operation, ReportClass, ValueClass, ValueOp,
    },
    BitmapKey, Deserialize, IterateParams, Key, Store, ValueKey, SUBSPACE_BITMAP_ID,
    SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT, SUBSPACE_INDEXES, SUBSPACE_LOGS, U32_LEN,
};

use super::DocumentSet;

#[cfg(feature = "test_mode")]
#[allow(clippy::type_complexity)]
static BITMAPS: std::sync::LazyLock<
    std::sync::Arc<
        parking_lot::Mutex<std::collections::HashMap<Vec<u8>, std::collections::HashSet<u32>>>,
    >,
> = std::sync::LazyLock::new(|| {
    std::sync::Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()))
});

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.get_value(key).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn get_bitmap(
        &self,
        key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.get_bitmap(key).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn get_bitmaps_intersection(
        &self,
        keys: Vec<BitmapKey<BitmapClass<u32>>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let mut result: Option<RoaringBitmap> = None;
        for key in keys {
            if let Some(bitmap) = self.get_bitmap(key).await.caused_by(trc::location!())? {
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
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let start_time = Instant::now();
        let result = match self {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.iterate(params, cb).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.get_counter(key).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        #[cfg(feature = "test_mode")]
        if std::env::var("PARANOID_WRITE").map_or(false, |v| v == "1") {
            let mut account_id = u32::MAX;
            let mut collection = u8::MAX;
            let mut document_id = u32::MAX;

            let mut bitmaps = Vec::new();
            let mut result = AssignedIds::default();

            for op in &batch.ops {
                match op {
                    Operation::AccountId {
                        account_id: account_id_,
                    } => {
                        account_id = *account_id_;
                    }
                    Operation::Collection {
                        collection: collection_,
                    } => {
                        collection = *collection_;
                    }
                    Operation::DocumentId {
                        document_id: document_id_,
                    } => {
                        document_id = *document_id_;
                    }
                    Operation::Bitmap { class, set } => {
                        if *set && matches!(class, BitmapClass::DocumentIds) {
                            let id = result.document_ids.len() as u32;
                            result.document_ids.push(id);
                        }

                        let key = class.serialize(
                            account_id,
                            collection,
                            document_id,
                            0,
                            (&result).into(),
                        );

                        bitmaps.push((key, class.clone(), document_id, *set));
                    }
                    _ => {}
                }
            }

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
                #[cfg(feature = "enterprise")]
                Self::SQLReadReplica(store) => store.write(batch).await,
                Self::None => Err(trc::StoreEvent::NotConfigured.into()),
            }
            .caused_by(trc::location!())?;

            for (key, class, document_id, set) in bitmaps {
                let mut bitmaps = BITMAPS.lock();
                let map = bitmaps.entry(key).or_default();
                if set {
                    if !map.insert(document_id) {
                        println!(
                            concat!(
                                "WARNING: key {:?} already contains document {} for account ",
                                "{}, collection {}"
                            ),
                            class, document_id, account_id, collection
                        );
                    }
                } else if !map.remove(&document_id) {
                    println!(
                        concat!(
                            "WARNING: key {:?} does not contain document {} for account ",
                            "{}, collection {}"
                        ),
                        class, document_id, account_id, collection
                    );
                }
            }

            return Ok(AssignedIds::default());
        }

        let start_time = Instant::now();
        let ops = batch.ops.len();

        let result = match self {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.write(batch).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        };

        trc::event!(
            Store(StoreEvent::DataWrite),
            Elapsed = start_time.elapsed(),
            Total = ops,
        );

        result
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        // Delete expired reports
        let now = now();
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Tls {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Arf { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Arf {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.purge_store().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.purge_store().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.purge_store().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.purge_store().await,
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.purge_store().await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_range(from, to).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_range(from, to).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_range(from, to).await,
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.delete_range(from, to).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_documents(
        &self,
        subspace: u8,
        account_id: u32,
        collection: u8,
        collection_offset: Option<usize>,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        // Serialize keys
        let (from_key, to_key) = if collection_offset.is_some() {
            (
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection),
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection + 1),
            )
        } else {
            (
                KeySerializer::new(U32_LEN).write(account_id),
                KeySerializer::new(U32_LEN).write(account_id + 1),
            )
        };

        // Find keys to delete
        let mut delete_keys = Vec::new();
        self.iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: from_key.finalize(),
                },
                AnyKey {
                    subspace,
                    key: to_key.finalize(),
                },
            )
            .no_values(),
            |key, _| {
                if collection_offset.map_or(true, |offset| {
                    key.get(key.len() - U32_LEN - offset).copied() == Some(collection)
                }) {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if document_ids.contains(document_id) {
                        delete_keys.push(key.to_vec());
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        // Remove keys
        let mut batch = BatchBuilder::new();

        for key in delete_keys {
            if batch.ops.len() >= 1000 {
                self.write(std::mem::take(&mut batch).build())
                    .await
                    .caused_by(trc::location!())?;
            }
            batch.ops.push(Operation::Value {
                class: ValueClass::Any(AnyClass { subspace, key }),
                op: ValueOp::Clear,
            });
        }

        if !batch.is_empty() {
            self.write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn purge_account(&self, account_id: u32) -> trc::Result<()> {
        for subspace in [
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
            SUBSPACE_LOGS,
            SUBSPACE_INDEXES,
        ] {
            self.delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id).finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id + 1).finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        for (from_class, to_class) in [
            (ValueClass::Acl(account_id), ValueClass::Acl(account_id + 1)),
            (ValueClass::Property(0), ValueClass::Property(0)),
            (
                ValueClass::FtsIndex(BitmapHash {
                    hash: [0u8; 8],
                    len: 0,
                }),
                ValueClass::FtsIndex(BitmapHash {
                    hash: [u8::MAX; 8],
                    len: u8::MAX,
                }),
            ),
        ] {
            self.delete_range(
                ValueKey {
                    account_id,
                    collection: 0,
                    document_id: 0,
                    class: from_class,
                },
                ValueKey {
                    account_id: account_id + 1,
                    collection: 0,
                    document_id: 0,
                    class: to_class,
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.get_blob(key, range).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.put_blob(key, data).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
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
            #[cfg(feature = "enterprise")]
            Self::SQLReadReplica(store) => store.delete_blob(key).await,
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        use crate::*;

        for subspace in [
            SUBSPACE_ACL,
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
            SUBSPACE_DIRECTORY,
            SUBSPACE_FTS_QUEUE,
            SUBSPACE_INDEXES,
            SUBSPACE_BLOB_RESERVE,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_LOGS,
            SUBSPACE_LOOKUP_VALUE,
            SUBSPACE_COUNTER,
            SUBSPACE_PROPERTY,
            SUBSPACE_SETTINGS,
            SUBSPACE_BLOBS,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_QUOTA,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_FTS_INDEX,
            SUBSPACE_TRACE,
            SUBSPACE_TRACE_INDEX,
        ] {
            self.delete_range(
                AnyKey {
                    subspace,
                    key: &[0u8],
                },
                AnyKey {
                    subspace,
                    key: &[
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                    ],
                },
            )
            .await
            .unwrap();
        }

        BITMAPS.lock().clear();
    }

    #[cfg(feature = "test_mode")]
    pub async fn blob_expire_all(&self) {
        use utils::{BlobHash, BLOB_HASH_LEN};

        use crate::{write::BlobOp, U64_LEN};

        // Delete all temporary hashes
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let mut batch = BatchBuilder::new();
        let mut last_account_id = u32::MAX;
        self.iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let account_id = key.deserialize_be_u32(0).caused_by(trc::location!())?;
                if account_id != last_account_id {
                    last_account_id = account_id;
                    batch.with_account_id(account_id);
                }

                batch.ops.push(Operation::Value {
                    class: ValueClass::Blob(BlobOp::Reserve {
                        hash: BlobHash::try_from_hash_slice(
                            key.get(U32_LEN..U32_LEN + BLOB_HASH_LEN).unwrap(),
                        )
                        .unwrap(),
                        until: key
                            .deserialize_be_u64(key.len() - U64_LEN)
                            .caused_by(trc::location!())?,
                    }),
                    op: ValueOp::Clear,
                });

                Ok(true)
            },
        )
        .await
        .unwrap();
        self.write(batch.build()).await.unwrap();
    }

    #[cfg(feature = "test_mode")]
    pub async fn lookup_expire_all(&self) {
        use crate::write::LookupClass;

        // Delete all temporary counters
        let from_key = ValueKey::from(ValueClass::Lookup(LookupClass::Key(vec![0u8])));
        let to_key = ValueKey::from(ValueClass::Lookup(LookupClass::Key(vec![u8::MAX; 10])));

        let mut expired_keys = Vec::new();
        let mut expired_counters = Vec::new();

        self.iterate(IterateParams::new(from_key, to_key), |key, value| {
            let expiry = value.deserialize_be_u64(0).caused_by(trc::location!())?;
            if expiry == 0 {
                expired_counters.push(key.to_vec());
            } else if expiry != u64::MAX {
                expired_keys.push(key.to_vec());
            }
            Ok(true)
        })
        .await
        .unwrap();

        if !expired_keys.is_empty() {
            let mut batch = BatchBuilder::new();
            for key in expired_keys {
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Key(key)),
                    op: ValueOp::Clear,
                });
                if batch.ops.len() >= 1000 {
                    self.write(batch.build()).await.unwrap();
                    batch = BatchBuilder::new();
                }
            }
            if !batch.ops.is_empty() {
                self.write(batch.build()).await.unwrap();
            }
        }

        if !expired_counters.is_empty() {
            let mut batch = BatchBuilder::new();
            for key in expired_counters {
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Counter(key.clone())),
                    op: ValueOp::Clear,
                });
                batch.ops.push(Operation::Value {
                    class: ValueClass::Lookup(LookupClass::Key(key)),
                    op: ValueOp::Clear,
                });
                if batch.ops.len() >= 1000 {
                    self.write(batch.build()).await.unwrap();
                    batch = BatchBuilder::new();
                }
            }
            if !batch.ops.is_empty() {
                self.write(batch.build()).await.unwrap();
            }
        }
    }

    #[cfg(feature = "test_mode")]
    #[allow(unused_variables)]

    pub async fn assert_is_empty(&self, blob_store: crate::BlobStore) {
        use utils::codec::leb128::Leb128Iterator;

        use crate::*;

        self.blob_expire_all().await;
        self.lookup_expire_all().await;
        self.purge_blobs(blob_store).await.unwrap();
        self.purge_store().await.unwrap();

        let store = self.clone();
        let mut failed = false;

        for (subspace, with_values) in [
            (SUBSPACE_ACL, true),
            //(SUBSPACE_DIRECTORY, true),
            (SUBSPACE_FTS_QUEUE, true),
            (SUBSPACE_LOOKUP_VALUE, true),
            (SUBSPACE_PROPERTY, true),
            (SUBSPACE_SETTINGS, true),
            (SUBSPACE_QUEUE_MESSAGE, true),
            (SUBSPACE_QUEUE_EVENT, true),
            (SUBSPACE_REPORT_OUT, true),
            (SUBSPACE_REPORT_IN, true),
            (SUBSPACE_FTS_INDEX, true),
            (SUBSPACE_BLOB_RESERVE, true),
            (SUBSPACE_BLOB_LINK, true),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_COUNTER, false),
            (SUBSPACE_QUOTA, false),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_BITMAP_ID, false),
            (SUBSPACE_BITMAP_TAG, false),
            (SUBSPACE_BITMAP_TEXT, false),
            (SUBSPACE_INDEXES, false),
            (SUBSPACE_TRACE, true),
            (SUBSPACE_TRACE_INDEX, false),
        ] {
            let from_key = crate::write::AnyKey {
                subspace,
                key: vec![0u8],
            };
            let to_key = crate::write::AnyKey {
                subspace,
                key: vec![u8::MAX; 10],
            };

            self.iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    match subspace {
                        SUBSPACE_BITMAP_ID | SUBSPACE_BITMAP_TAG | SUBSPACE_BITMAP_TEXT => {
                            if key.get(0..4).unwrap_or_default() == u32::MAX.to_be_bytes() {
                                return Ok(true);
                            }

                            const BM_DOCUMENT_IDS: u8 = 0;
                            const BM_TAG: u8 = 1 << 6;
                            const BM_TEXT: u8 = 1 << 7;
                            const TAG_TEXT: u8 = 1 << 0;
                            const TAG_STATIC: u8 = 1 << 1;

                            match key[5] {
                                BM_DOCUMENT_IDS => {
                                    print!("Found document ids bitmap");
                                }
                                BM_TAG => {
                                    print!(
                                        "Found tagged id {} bitmap",
                                        key[7..].iter().next_leb128::<u32>().unwrap()
                                    );
                                }
                                TAG_TEXT => {
                                    print!(
                                        "Found tagged text {:?} bitmap",
                                        String::from_utf8_lossy(&key[7..])
                                    );
                                }
                                TAG_STATIC => {
                                    print!("Found tagged static {} bitmap", key[7]);
                                }
                                other => {
                                    if other & BM_TEXT == BM_TEXT {
                                        print!(
                                            "Found text hash {:?} bitmap",
                                            String::from_utf8_lossy(&key[7..])
                                        );
                                    } else {
                                        print!("Found unknown bitmap");
                                    }
                                }
                            }

                            println!(
                                concat!(
                                    ", account {}, collection {},",
                                    " family {}, field {}, key {:?}: {:?}"
                                ),
                                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                key[4],
                                key[5],
                                key[6],
                                key,
                                value
                            );
                        }
                        SUBSPACE_INDEXES => {
                            println!(
                                concat!(
                                    "Found index key, account {}, collection {}, ",
                                    "document {}, property {}, value {:?}: {:?}"
                                ),
                                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                key[4],
                                u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                                key[5],
                                String::from_utf8_lossy(&key[6..key.len() - 4]),
                                key
                            );
                        }
                        _ => {
                            println!(
                                "Found key in {:?}: {:?} {:?}",
                                char::from(subspace),
                                key,
                                value
                            );
                        }
                    }
                    failed = true;

                    Ok(true)
                },
            )
            .await
            .unwrap();
        }

        // Delete logs
        self.delete_range(
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[0u8],
            },
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                ],
            },
        )
        .await
        .unwrap();

        if failed {
            panic!("Store is not empty.");
        }
    }
}
