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
use utils::config::{utils::AsKey, Config};

use crate::{
    backend::{fs::FsStore, memory::MemoryStore},
    Lookup, LookupStore, Store, Stores,
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

#[async_trait]
pub trait ConfigStore {
    async fn parse_stores(&self) -> utils::config::Result<Stores>;
}

#[async_trait]
impl ConfigStore for Config {
    async fn parse_stores(&self) -> utils::config::Result<Stores> {
        let mut config = Stores::default();

        for id in self.sub_keys("store") {
            // Parse directory
            let protocol = self
                .value_require(("store", id, "type"))?
                .to_ascii_lowercase();
            let prefix = ("store", id);
            let store_id = id.to_string();

            let lookup_store = match protocol.as_str() {
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
                    db
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
                    db
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
                "memory" => {
                    let prefix = prefix.as_key();
                    for lookup_id in self.sub_keys((&prefix, "lookup")) {
                        config.lookups.insert(
                            format!("{store_id}/{lookup_id}"),
                            Arc::new(Lookup {
                                store: MemoryStore::open(
                                    self,
                                    (prefix.as_str(), "lookup", lookup_id),
                                )
                                .await?
                                .into(),
                                query: String::new(),
                            }),
                        );
                    }
                    continue;
                }

                unknown => {
                    tracing::debug!("Unknown directory type: {unknown:?}");
                    continue;
                }
            };

            // Add queries
            let lookup_store: LookupStore = lookup_store.into();
            for lookup_id in self.sub_keys(("store", id, "query")) {
                config.lookups.insert(
                    format!("{store_id}/{lookup_id}"),
                    Arc::new(Lookup {
                        store: lookup_store.clone(),
                        query: self.property_require(("store", id, "query", lookup_id))?,
                    }),
                );
            }
            config.lookup_stores.insert(store_id, lookup_store.clone());

            // Run init queries on database
            for (_, query) in self.values(("store", id, "init")) {
                if let Err(err) = lookup_store.query::<usize>(query, Vec::new()).await {
                    tracing::warn!("Failed to initialize store {id:?}: {err}");
                }
            }
        }

        Ok(config)
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
