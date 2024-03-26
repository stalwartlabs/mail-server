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

use std::sync::Arc;

use utils::config::{cron::SimpleCron, Config};

use crate::{
    backend::fs::FsStore,
    write::purge::{PurgeSchedule, PurgeStore},
    BlobStore, CompressionAlgo, FtsStore, LookupStore, QueryStore, Store, Stores,
};

#[cfg(feature = "s3")]
use crate::backend::s3::S3Store;

#[cfg(feature = "postgres")]
use crate::backend::postgres::PostgresStore;

#[cfg(feature = "mysql")]
use crate::backend::mysql::MysqlStore;

#[cfg(feature = "sqlite")]
use crate::backend::sqlite::SqliteStore;

#[cfg(feature = "foundation")]
use crate::backend::foundationdb::FdbStore;

#[cfg(feature = "rocks")]
use crate::backend::rocksdb::RocksDbStore;

#[cfg(feature = "elastic")]
use crate::backend::elastic::ElasticSearchStore;

#[cfg(feature = "redis")]
use crate::backend::redis::RedisStore;

impl Stores {
    pub async fn parse(config: &mut Config) -> Self {
        let mut stores = Stores::default();
        let ids = config
            .sub_keys("store", ".type")
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        for id in ids {
            let id = id.as_str();
            // Parse store
            #[cfg(feature = "test_mode")]
            {
                if config
                    .property_or_default::<bool>(("store", id, "disable"), "false")
                    .unwrap_or(false)
                {
                    tracing::debug!("Skipping disabled store {id:?}.");
                    continue;
                }
            }
            let protocol = if let Some(protocol) = config.value_require(("store", id, "type")) {
                protocol.to_ascii_lowercase()
            } else {
                continue;
            };
            let prefix = ("store", id);
            let store_id = id.to_string();
            let compression_algo = config
                .property_or_default::<CompressionAlgo>(("store", id, "compression"), "none")
                .unwrap_or(CompressionAlgo::None);

            let lookup_store: Store = match protocol.as_str() {
                #[cfg(feature = "rocks")]
                "rocksdb" => {
                    if let Some(db) = RocksDbStore::open(config, prefix).await.map(Store::from) {
                        stores.stores.insert(store_id.clone(), db.clone());
                        stores
                            .fts_stores
                            .insert(store_id.clone(), db.clone().into());
                        stores.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        stores.lookup_stores.insert(store_id, db.into());
                    }
                    continue;
                }
                #[cfg(feature = "foundation")]
                "foundationdb" => {
                    if let Some(db) = FdbStore::open(config, prefix).await.map(Store::from) {
                        stores.stores.insert(store_id.clone(), db.clone());
                        stores
                            .fts_stores
                            .insert(store_id.clone(), db.clone().into());
                        stores.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        stores.lookup_stores.insert(store_id, db.into());
                    }
                    continue;
                }
                #[cfg(feature = "postgres")]
                "postgresql" => {
                    if let Some(db) = PostgresStore::open(config, prefix).await.map(Store::from) {
                        stores.stores.insert(store_id.clone(), db.clone());
                        stores
                            .fts_stores
                            .insert(store_id.clone(), db.clone().into());
                        stores.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        db
                    } else {
                        continue;
                    }
                }
                #[cfg(feature = "mysql")]
                "mysql" => {
                    if let Some(db) = MysqlStore::open(config, prefix).await.map(Store::from) {
                        stores.stores.insert(store_id.clone(), db.clone());
                        stores
                            .fts_stores
                            .insert(store_id.clone(), db.clone().into());
                        stores.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        db
                    } else {
                        continue;
                    }
                }
                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    if let Some(db) = SqliteStore::open(config, prefix).map(Store::from) {
                        stores.stores.insert(store_id.clone(), db.clone());
                        stores
                            .fts_stores
                            .insert(store_id.clone(), db.clone().into());
                        stores.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        db
                    } else {
                        continue;
                    }
                }
                "fs" => {
                    if let Some(db) = FsStore::open(config, prefix).await.map(BlobStore::from) {
                        stores
                            .blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                    continue;
                }
                #[cfg(feature = "s3")]
                "s3" => {
                    if let Some(db) = S3Store::open(config, prefix).await.map(BlobStore::from) {
                        stores
                            .blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                    continue;
                }
                #[cfg(feature = "elastic")]
                "elasticsearch" => {
                    if let Some(db) = ElasticSearchStore::open(config, prefix)
                        .await
                        .map(FtsStore::from)
                    {
                        stores.fts_stores.insert(store_id, db);
                    }
                    continue;
                }
                #[cfg(feature = "redis")]
                "redis" => {
                    if let Some(db) = RedisStore::open(config, prefix)
                        .await
                        .map(LookupStore::from)
                    {
                        stores.lookup_stores.insert(store_id, db);
                    }
                    continue;
                }
                unknown => {
                    tracing::debug!("Unknown directory type: {unknown:?}");
                    continue;
                }
            };

            // Add queries as lookup stores
            let lookup_store: LookupStore = lookup_store.into();
            for lookup_id in config.sub_keys(("store", id, "query"), "") {
                if let Some(query) = config.value(("store", id, "query", lookup_id)) {
                    stores.lookup_stores.insert(
                        format!("{store_id}/{lookup_id}"),
                        LookupStore::Query(Arc::new(QueryStore {
                            store: lookup_store.clone(),
                            query: query.to_string(),
                        })),
                    );
                }
            }
            stores.lookup_stores.insert(store_id, lookup_store.clone());

            // Run init queries on database
            for query in config
                .values(("store", id, "init.execute"))
                .map(|(_, s)| s.to_string())
                .collect::<Vec<_>>()
            {
                if let Err(err) = lookup_store.query::<usize>(&query, Vec::new()).await {
                    config.new_build_error(
                        ("store", id),
                        format!("Failed to initialize store: {err}"),
                    );
                }
            }
        }

        // Parse purge schedules
        if let Some(store) = config
            .value("storage.data")
            .and_then(|store_id| stores.stores.get(store_id))
        {
            let store_id = config.value("storage.data").unwrap().to_string();
            if let Some(cron) =
                config.property::<SimpleCron>(("store", store_id.as_str(), "purge.frequency"))
            {
                stores.purge_schedules.push(PurgeSchedule {
                    cron,
                    store_id,
                    store: PurgeStore::Data(store.clone()),
                });
            }

            if let Some(blob_store) = config
                .value("storage.blob")
                .and_then(|blob_store_id| stores.blob_stores.get(blob_store_id))
            {
                let store_id = config.value("storage.blob").unwrap().to_string();
                if let Some(cron) =
                    config.property::<SimpleCron>(("store", store_id.as_str(), "purge.frequency"))
                {
                    stores.purge_schedules.push(PurgeSchedule {
                        cron,
                        store_id,
                        store: PurgeStore::Blobs {
                            store: store.clone(),
                            blob_store: blob_store.clone(),
                        },
                    });
                }
            }
        }
        for (store_id, store) in &stores.lookup_stores {
            if let Some(cron) =
                config.property::<SimpleCron>(("store", store_id.as_str(), "purge.frequency"))
            {
                stores.purge_schedules.push(PurgeSchedule {
                    cron,
                    store_id: store_id.clone(),
                    store: PurgeStore::Lookup(store.clone()),
                });
            }
        }

        stores
    }
}

impl From<crate::Error> for String {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::InternalError(err) => err,
            crate::Error::AssertValueFailed => unimplemented!(),
        }
    }
}
