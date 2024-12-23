/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{cron::SimpleCron, utils::ParseValue, Config};

use crate::{
    backend::fs::FsStore, BlobStore, CompressionAlgo, InMemoryStore, PurgeSchedule, PurgeStore,
    Store, Stores,
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

#[cfg(feature = "azure")]
use crate::backend::azure::AzureStore;

impl Stores {
    pub async fn parse_all(config: &mut Config) -> Self {
        let mut stores = Self::parse(config).await;
        stores.parse_in_memory(config).await;
        stores
    }

    pub async fn parse(config: &mut Config) -> Self {
        let mut stores = Self::default();
        stores.parse_stores(config).await;
        stores
    }

    pub async fn parse_stores(&mut self, config: &mut Config) {
        let is_reload = !self.stores.is_empty();
        #[cfg(feature = "enterprise")]
        let mut composite_stores = Vec::new();
        let store_ids = config
            .sub_keys("store", ".type")
            .map(|id| id.to_string())
            .collect::<Vec<_>>();

        for id in store_ids {
            let id = id.as_str();
            // Parse store
            #[cfg(feature = "test_mode")]
            {
                if config
                    .property_or_default::<bool>(("store", id, "disable"), "false")
                    .unwrap_or(false)
                {
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

            match protocol.as_str() {
                #[cfg(feature = "rocks")]
                "rocksdb" => {
                    // Avoid opening the same store twice
                    if is_reload
                        && self
                            .stores
                            .values()
                            .any(|store| matches!(store, Store::RocksDb(_)))
                    {
                        continue;
                    }

                    if let Some(db) = RocksDbStore::open(config, prefix).await.map(Store::from) {
                        self.stores.insert(store_id.clone(), db.clone());
                        self.fts_stores.insert(store_id.clone(), db.clone().into());
                        self.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        self.in_memory_stores.insert(store_id, db.into());
                    }
                }
                #[cfg(feature = "foundation")]
                "foundationdb" => {
                    // Avoid opening the same store twice
                    if is_reload
                        && self
                            .stores
                            .values()
                            .any(|store| matches!(store, Store::FoundationDb(_)))
                    {
                        continue;
                    }

                    if let Some(db) = FdbStore::open(config, prefix).await.map(Store::from) {
                        self.stores.insert(store_id.clone(), db.clone());
                        self.fts_stores.insert(store_id.clone(), db.clone().into());
                        self.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        self.in_memory_stores.insert(store_id, db.into());
                    }
                }
                #[cfg(feature = "postgres")]
                "postgresql" => {
                    if let Some(db) =
                        PostgresStore::open(config, prefix, config.is_active_store(id))
                            .await
                            .map(Store::from)
                    {
                        self.stores.insert(store_id.clone(), db.clone());
                        self.fts_stores.insert(store_id.clone(), db.clone().into());
                        self.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        self.in_memory_stores.insert(store_id.clone(), db.into());
                    }
                }
                #[cfg(feature = "mysql")]
                "mysql" => {
                    if let Some(db) = MysqlStore::open(config, prefix, config.is_active_store(id))
                        .await
                        .map(Store::from)
                    {
                        self.stores.insert(store_id.clone(), db.clone());
                        self.fts_stores.insert(store_id.clone(), db.clone().into());
                        self.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        self.in_memory_stores.insert(store_id.clone(), db.into());
                    }
                }
                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    // Avoid opening the same store twice
                    if is_reload
                        && self
                            .stores
                            .values()
                            .any(|store| matches!(store, Store::SQLite(_)))
                    {
                        continue;
                    }

                    if let Some(db) = SqliteStore::open(config, prefix).map(Store::from) {
                        self.stores.insert(store_id.clone(), db.clone());
                        self.fts_stores.insert(store_id.clone(), db.clone().into());
                        self.blob_stores.insert(
                            store_id.clone(),
                            BlobStore::from(db.clone()).with_compression(compression_algo),
                        );
                        self.in_memory_stores.insert(store_id.clone(), db.into());
                    }
                }
                "fs" => {
                    if let Some(db) = FsStore::open(config, prefix).await.map(BlobStore::from) {
                        self.blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                }
                #[cfg(feature = "s3")]
                "s3" => {
                    if let Some(db) = S3Store::open(config, prefix).await.map(BlobStore::from) {
                        self.blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                }
                #[cfg(feature = "elastic")]
                "elasticsearch" => {
                    if let Some(db) = ElasticSearchStore::open(config, prefix)
                        .await
                        .map(crate::FtsStore::from)
                    {
                        self.fts_stores.insert(store_id, db);
                    }
                }
                #[cfg(feature = "redis")]
                "redis" => {
                    if let Some(db) = RedisStore::open(config, prefix)
                        .await
                        .map(InMemoryStore::from)
                    {
                        self.in_memory_stores.insert(store_id, db);
                    }
                }
                #[cfg(feature = "enterprise")]
                "sql-read-replica" | "distributed-blob" => {
                    composite_stores.push((store_id, protocol));
                }
                #[cfg(feature = "azure")]
                "azure" => {
                    if let Some(db) = AzureStore::open(config, prefix).await.map(BlobStore::from) {
                        self.blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                }
                unknown => {
                    config.new_parse_warning(
                        ("store", id, "type"),
                        format!("Unknown directory type: {unknown:?}"),
                    );
                }
            }
        }

        #[cfg(feature = "enterprise")]
        for (id, protocol) in composite_stores {
            let prefix = ("store", id.as_str());
            let compression = config
                .property_or_default::<CompressionAlgo>(
                    ("store", id.as_str(), "compression"),
                    "none",
                )
                .unwrap_or(CompressionAlgo::None);
            match protocol.as_str() {
                #[cfg(any(feature = "postgres", feature = "mysql"))]
                "sql-read-replica" => {
                    if let Some(db) = crate::backend::composite::read_replica::SQLReadReplica::open(
                        config,
                        prefix,
                        self,
                        config.is_active_store(&id),
                    )
                    .await
                    {
                        let db = Store::SQLReadReplica(db.into());
                        self.stores.insert(id.to_string(), db.clone());
                        self.fts_stores.insert(id.to_string(), db.clone().into());
                        self.blob_stores.insert(
                            id.to_string(),
                            BlobStore::from(db.clone()).with_compression(compression),
                        );
                        self.in_memory_stores.insert(id.to_string(), db.into());
                    }
                }
                "sharded-blob" | "distributed-blob" => {
                    if let Some(db) = crate::backend::composite::sharded_blob::ShardedBlob::open(
                        config, prefix, self,
                    ) {
                        let store = BlobStore {
                            backend: crate::BlobBackend::Sharded(db.into()),
                            compression,
                        };
                        self.blob_stores.insert(id, store);
                    }
                }
                _ => (),
            }
        }
    }

    pub async fn parse_in_memory(&mut self, config: &mut Config) {
        // Parse memory stores
        self.parse_static_stores(config);

        // Parse http stores
        self.parse_http_stores(config);

        // Parse purge schedules
        if let Some(store) = config
            .value("storage.data")
            .and_then(|store_id| self.stores.get(store_id))
        {
            let store_id = config.value("storage.data").unwrap().to_string();
            self.purge_schedules.push(PurgeSchedule {
                cron: config
                    .property_or_default::<SimpleCron>(
                        ("store", store_id.as_str(), "purge.frequency"),
                        "0 3 *",
                    )
                    .unwrap_or_else(|| SimpleCron::parse_value("0 3 *").unwrap()),
                store_id,
                store: PurgeStore::Data(store.clone()),
            });

            if let Some(blob_store) = config
                .value("storage.blob")
                .and_then(|blob_store_id| self.blob_stores.get(blob_store_id))
            {
                let store_id = config.value("storage.blob").unwrap().to_string();
                self.purge_schedules.push(PurgeSchedule {
                    cron: config
                        .property_or_default::<SimpleCron>(
                            ("store", store_id.as_str(), "purge.frequency"),
                            "0 4 *",
                        )
                        .unwrap_or_else(|| SimpleCron::parse_value("0 4 *").unwrap()),
                    store_id,
                    store: PurgeStore::Blobs {
                        store: store.clone(),
                        blob_store: blob_store.clone(),
                    },
                });
            }
        }
        for (store_id, store) in &self.in_memory_stores {
            if matches!(store, InMemoryStore::Store(_)) {
                self.purge_schedules.push(PurgeSchedule {
                    cron: config
                        .property_or_default::<SimpleCron>(
                            ("store", store_id.as_str(), "purge.frequency"),
                            "0 5 *",
                        )
                        .unwrap_or_else(|| SimpleCron::parse_value("0 5 *").unwrap()),
                    store_id: store_id.clone(),
                    store: PurgeStore::Lookup(store.clone()),
                });
            }
        }
    }
}

#[allow(dead_code)]
trait IsActiveStore {
    fn is_active_store(&self, id: &str) -> bool;
}

impl IsActiveStore for Config {
    fn is_active_store(&self, id: &str) -> bool {
        for key in [
            "storage.data",
            "storage.blob",
            "storage.lookup",
            "storage.fts",
            "tracing.history.store",
            "metrics.history.store",
        ] {
            if let Some(store_id) = self.value(key) {
                if store_id == id {
                    return true;
                }
            }
        }

        false
    }
}
