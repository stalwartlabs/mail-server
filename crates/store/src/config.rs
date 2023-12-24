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

use async_trait::async_trait;
use utils::config::{cron::SimpleCron, Config};

use crate::{
    backend::{fs::FsStore, memory::MemoryStore},
    write::purge::{PurgeSchedule, PurgeStore},
    LookupStore, QueryStore, Store, Stores,
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

#[async_trait]
pub trait ConfigStore {
    async fn parse_stores(&self) -> utils::config::Result<Stores>;
    async fn parse_purge_schedules(
        &self,
        stores: &Stores,
        store: Option<&str>,
        blob_store: Option<&str>,
    ) -> utils::config::Result<Vec<PurgeSchedule>>;
}

#[async_trait]
impl ConfigStore for Config {
    #[allow(unused_variables)]
    #[allow(unreachable_code)]
    async fn parse_stores(&self) -> utils::config::Result<Stores> {
        let mut config = Stores::default();

        for id in self.sub_keys("store") {
            // Parse store
            if self.property_or_static::<bool>(("store", id, "disable"), "false")? {
                tracing::debug!("Skipping disabled store {id:?}.");
                continue;
            }
            let protocol = self
                .value_require(("store", id, "type"))?
                .to_ascii_lowercase();
            let prefix = ("store", id);
            let store_id = id.to_string();

            let lookup_store: Store = match protocol.as_str() {
                #[cfg(feature = "rocks")]
                "rocksdb" => {
                    let db: Store = RocksDbStore::open(self, prefix).await?.into();
                    config.stores.insert(store_id.clone(), db.clone());
                    config
                        .fts_stores
                        .insert(store_id.clone(), db.clone().into());
                    config
                        .blob_stores
                        .insert(store_id.clone(), db.clone().into());
                    config.lookup_stores.insert(store_id, db.into());
                    continue;
                }
                #[cfg(feature = "foundation")]
                "foundationdb" => {
                    let db: Store = FdbStore::open(self, prefix).await?.into();
                    config.stores.insert(store_id.clone(), db.clone());
                    config
                        .fts_stores
                        .insert(store_id.clone(), db.clone().into());
                    config
                        .blob_stores
                        .insert(store_id.clone(), db.clone().into());
                    config.lookup_stores.insert(store_id, db.into());
                    continue;
                }
                #[cfg(feature = "postgres")]
                "postgresql" => {
                    let db: Store = PostgresStore::open(self, prefix).await?.into();
                    config.stores.insert(store_id.clone(), db.clone());
                    config
                        .fts_stores
                        .insert(store_id.clone(), db.clone().into());
                    config
                        .blob_stores
                        .insert(store_id.clone(), db.clone().into());
                    db
                }
                #[cfg(feature = "mysql")]
                "mysql" => {
                    let db: Store = MysqlStore::open(self, prefix).await?.into();
                    config.stores.insert(store_id.clone(), db.clone());
                    config
                        .fts_stores
                        .insert(store_id.clone(), db.clone().into());
                    config
                        .blob_stores
                        .insert(store_id.clone(), db.clone().into());
                    db
                }
                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let db: Store = SqliteStore::open(self, prefix).await?.into();
                    config.stores.insert(store_id.clone(), db.clone());
                    config
                        .fts_stores
                        .insert(store_id.clone(), db.clone().into());
                    config
                        .blob_stores
                        .insert(store_id.clone(), db.clone().into());
                    db
                }
                "fs" => {
                    config
                        .blob_stores
                        .insert(store_id, FsStore::open(self, prefix).await?.into());
                    continue;
                }
                #[cfg(feature = "s3")]
                "s3" => {
                    config
                        .blob_stores
                        .insert(store_id, S3Store::open(self, prefix).await?.into());
                    continue;
                }
                #[cfg(feature = "elastic")]
                "elasticsearch" => {
                    config.fts_stores.insert(
                        store_id,
                        ElasticSearchStore::open(self, prefix).await?.into(),
                    );
                    continue;
                }
                #[cfg(feature = "redis")]
                "redis" => {
                    config
                        .lookup_stores
                        .insert(store_id, RedisStore::open(self, prefix).await?.into());
                    continue;
                }
                "memory" => {
                    config
                        .lookup_stores
                        .insert(store_id, MemoryStore::open(self, prefix).await?.into());
                    continue;
                }

                unknown => {
                    tracing::debug!("Unknown directory type: {unknown:?}");
                    continue;
                }
            };

            // Add queries as lookup stores
            let lookup_store: LookupStore = lookup_store.into();
            for lookup_id in self.sub_keys(("store", id, "query")) {
                config.lookup_stores.insert(
                    format!("{store_id}/{lookup_id}"),
                    LookupStore::Query(Arc::new(QueryStore {
                        store: lookup_store.clone(),
                        query: self.property_require(("store", id, "query", lookup_id))?,
                    })),
                );
            }
            config.lookup_stores.insert(store_id, lookup_store.clone());

            // Run init queries on database
            for (_, query) in self.values(("store", id, "init.execute")) {
                if let Err(err) = lookup_store.query::<usize>(query, Vec::new()).await {
                    tracing::warn!("Failed to initialize store {id:?}: {err}");
                }
            }
        }

        Ok(config)
    }

    async fn parse_purge_schedules(
        &self,
        stores: &Stores,
        store_id: Option<&str>,
        blob_store_id: Option<&str>,
    ) -> utils::config::Result<Vec<PurgeSchedule>> {
        let mut schedules = Vec::new();

        if let Some(store) = store_id.and_then(|store_id| stores.stores.get(store_id)) {
            let store_id = store_id.unwrap();
            if let Some(cron) =
                self.property::<SimpleCron>(("store", store_id, "purge.frequency"))?
            {
                schedules.push(PurgeSchedule {
                    cron,
                    store_id: store_id.to_string(),
                    store: PurgeStore::Bitmaps(store.clone()),
                });
            }

            if let Some(blob_store) =
                blob_store_id.and_then(|blob_store_id| stores.blob_stores.get(blob_store_id))
            {
                let blob_store_id = blob_store_id.unwrap();
                if let Some(cron) =
                    self.property::<SimpleCron>(("store", blob_store_id, "purge.frequency"))?
                {
                    schedules.push(PurgeSchedule {
                        cron,
                        store_id: blob_store_id.to_string(),
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
                self.property::<SimpleCron>(("store", store_id.as_str(), "purge.frequency"))?
            {
                schedules.push(PurgeSchedule {
                    cron,
                    store_id: store_id.clone(),
                    store: PurgeStore::Lookup(store.clone()),
                });
            }
        }

        Ok(schedules)
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
