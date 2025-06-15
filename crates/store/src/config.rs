/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    BlobStore, CompressionAlgo, InMemoryStore, PurgeSchedule, PurgeStore, Store, Stores,
    backend::fs::FsStore,
};
use utils::config::{Config, cron::SimpleCron, utils::ParseValue};

#[cfg(feature = "enterprise")]
enum CompositeStore {
    #[cfg(any(feature = "postgres", feature = "mysql"))]
    SQLReadReplica(String),
    ShardedBlob(String),
    ShardedInMemory(String),
}

impl Stores {
    pub async fn parse_all(config: &mut Config, is_reload: bool) -> Self {
        let mut stores = Self::parse(config).await;
        stores.parse_in_memory(config, is_reload).await;
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

        for store_id in store_ids {
            let id = store_id.as_str();
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

                    if let Some(db) = crate::backend::rocksdb::RocksDbStore::open(config, prefix)
                        .await
                        .map(Store::from)
                    {
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

                    if let Some(db) = crate::backend::foundationdb::FdbStore::open(config, prefix)
                        .await
                        .map(Store::from)
                    {
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
                    if let Some(db) = crate::backend::postgres::PostgresStore::open(
                        config,
                        prefix,
                        config.is_active_store(id),
                    )
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
                    if let Some(db) = crate::backend::mysql::MysqlStore::open(
                        config,
                        prefix,
                        config.is_active_store(id),
                    )
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

                    if let Some(db) =
                        crate::backend::sqlite::SqliteStore::open(config, prefix).map(Store::from)
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
                "fs" => {
                    if let Some(db) = FsStore::open(config, prefix).await.map(BlobStore::from) {
                        self.blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                }
                #[cfg(feature = "s3")]
                "s3" => {
                    if let Some(db) = crate::backend::s3::S3Store::open(config, prefix)
                        .await
                        .map(BlobStore::from)
                    {
                        self.blob_stores
                            .insert(store_id, db.with_compression(compression_algo));
                    }
                }
                #[cfg(feature = "elastic")]
                "elasticsearch" => {
                    if let Some(db) =
                        crate::backend::elastic::ElasticSearchStore::open(config, prefix)
                            .await
                            .map(crate::FtsStore::from)
                    {
                        self.fts_stores.insert(store_id, db);
                    }
                }
                #[cfg(feature = "redis")]
                "redis" => {
                    if let Some(db) = crate::backend::redis::RedisStore::open(config, prefix)
                        .await
                        .map(std::sync::Arc::new)
                    {
                        self.in_memory_stores
                            .insert(store_id.clone(), InMemoryStore::Redis(db.clone()));
                        self.pubsub_stores
                            .insert(store_id, crate::PubSubStore::Redis(db));
                    }
                }
                #[cfg(feature = "nats")]
                "nats" => {
                    if let Some(db) = crate::backend::nats::NatsPubSub::open(config, prefix)
                        .await
                        .map(std::sync::Arc::new)
                    {
                        self.pubsub_stores
                            .insert(store_id, crate::PubSubStore::Nats(db));
                    }
                }
                #[cfg(feature = "zenoh")]
                "zenoh" => {
                    if let Some(db) = crate::backend::zenoh::ZenohPubSub::open(config, prefix)
                        .await
                        .map(std::sync::Arc::new)
                    {
                        self.pubsub_stores
                            .insert(store_id, crate::PubSubStore::Zenoh(db));
                    }
                }
                #[cfg(feature = "kafka")]
                "kafka" => {
                    if let Some(db) = crate::backend::kafka::KafkaPubSub::open(config, prefix)
                        .await
                        .map(std::sync::Arc::new)
                    {
                        self.pubsub_stores
                            .insert(store_id, crate::PubSubStore::Kafka(db));
                    }
                }
                #[cfg(feature = "enterprise")]
                "sql-read-replica" => {
                    #[cfg(any(feature = "postgres", feature = "mysql"))]
                    composite_stores.push(CompositeStore::SQLReadReplica(store_id));
                }
                #[cfg(feature = "enterprise")]
                "distributed-blob" | "sharded-blob" => {
                    composite_stores.push(CompositeStore::ShardedBlob(store_id));
                }
                #[cfg(feature = "enterprise")]
                "sharded-in-memory" => {
                    composite_stores.push(CompositeStore::ShardedInMemory(store_id));
                }
                #[cfg(feature = "azure")]
                "azure" => {
                    if let Some(db) = crate::backend::azure::AzureStore::open(config, prefix)
                        .await
                        .map(BlobStore::from)
                    {
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
        for composite_store in composite_stores {
            match composite_store {
                #[cfg(any(feature = "postgres", feature = "mysql"))]
                CompositeStore::SQLReadReplica(id) => {
                    let prefix = ("store", id.as_str());
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
                            BlobStore::from(db.clone()).with_compression(
                                config
                                    .property_or_default::<CompressionAlgo>(
                                        ("store", id.as_str(), "compression"),
                                        "none",
                                    )
                                    .unwrap_or(CompressionAlgo::None),
                            ),
                        );
                        self.in_memory_stores.insert(id, db.into());
                    }
                }
                CompositeStore::ShardedBlob(id) => {
                    let prefix = ("store", id.as_str());
                    if let Some(db) = crate::backend::composite::sharded_blob::ShardedBlob::open(
                        config, prefix, self,
                    ) {
                        let store = BlobStore {
                            backend: crate::BlobBackend::Sharded(db.into()),
                            compression: config
                                .property_or_default::<CompressionAlgo>(
                                    ("store", id.as_str(), "compression"),
                                    "none",
                                )
                                .unwrap_or(CompressionAlgo::None),
                        };
                        self.blob_stores.insert(id, store);
                    }
                }
                CompositeStore::ShardedInMemory(id) => {
                    let prefix = ("store", id.as_str());
                    if let Some(db) =
                        crate::backend::composite::sharded_lookup::ShardedInMemory::open(
                            config, prefix, self,
                        )
                    {
                        self.in_memory_stores
                            .insert(id, InMemoryStore::Sharded(db.into()));
                    }
                }
            }
        }
    }

    pub async fn parse_in_memory(&mut self, config: &mut Config, is_reload: bool) {
        // Parse memory stores
        self.parse_static_stores(config, is_reload);

        // Parse http stores
        self.parse_http_stores(config, is_reload);

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
            if matches!(store, InMemoryStore::Store(_))
                && config.is_active_in_memory_store(store_id)
            {
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
    fn is_active_in_memory_store(&self, id: &str) -> bool;
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

    fn is_active_in_memory_store(&self, id: &str) -> bool {
        self.value("storage.lookup")
            .is_some_and(|store_id| store_id == id)
    }
}
