/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use utils::config::{cron::SimpleCron, utils::ParseValue, Config};

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
    pub async fn parse_all(config: &mut Config) -> Self {
        let mut stores = Self::parse(config).await;
        stores.parse_lookups(config).await;
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
                        self.lookup_stores.insert(store_id, db.into());
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
                        self.lookup_stores.insert(store_id, db.into());
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
                        self.lookup_stores.insert(store_id.clone(), db.into());
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
                        self.lookup_stores.insert(store_id.clone(), db.into());
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
                        self.lookup_stores.insert(store_id.clone(), db.into());
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
                        .map(FtsStore::from)
                    {
                        self.fts_stores.insert(store_id, db);
                    }
                }
                #[cfg(feature = "redis")]
                "redis" => {
                    if let Some(db) = RedisStore::open(config, prefix)
                        .await
                        .map(LookupStore::from)
                    {
                        self.lookup_stores.insert(store_id, db);
                    }
                }
                #[cfg(feature = "enterprise")]
                "sql-read-replica" | "composite-blob" => {
                    composite_stores.push((store_id, protocol));
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
                        self.lookup_stores.insert(id.to_string(), db.into());
                    }
                }
                "composite-blob" => {
                    if let Some(db) =
                        crate::backend::composite::distributed_blob::CompositeBlob::open(
                            config, prefix, self,
                        )
                    {
                        let store = BlobStore {
                            backend: crate::BlobBackend::Composite(db.into()),
                            compression,
                        };
                        self.blob_stores.insert(id, store);
                    }
                }
                _ => (),
            }
        }
    }

    pub async fn parse_lookups(&mut self, config: &mut Config) {
        // Parse memory stores
        self.parse_memory_stores(config);

        // Add SQL queries as lookup stores
        for (store_id, lookup_store) in self.stores.iter().filter_map(|(id, store)| {
            if store.is_sql() {
                Some((id.clone(), LookupStore::from(store.clone())))
            } else {
                None
            }
        }) {
            // Add queries as lookup stores
            for lookup_id in config.sub_keys(("store", store_id.as_str(), "query"), "") {
                if let Some(query) = config.value(("store", store_id.as_str(), "query", lookup_id))
                {
                    self.lookup_stores.insert(
                        format!("{store_id}/{lookup_id}"),
                        LookupStore::Query(Arc::new(QueryStore {
                            store: lookup_store.clone(),
                            query: query.to_string(),
                        })),
                    );
                }
            }

            // Run init queries on database
            for query in config
                .values(("store", store_id.as_str(), "init.execute"))
                .map(|(_, s)| s.to_string())
                .collect::<Vec<_>>()
            {
                if let Err(err) = lookup_store.query::<usize>(&query, Vec::new()).await {
                    config.new_build_error(
                        ("store", store_id.as_str()),
                        format!("Failed to initialize store: {err}"),
                    );
                }
            }
        }

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
        for (store_id, store) in &self.lookup_stores {
            if matches!(store, LookupStore::Store(_)) {
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
