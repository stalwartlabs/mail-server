/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::{
    future::Future,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use roaring::RoaringBitmap;
use utils::config::{utils::AsKey, Config};

use crate::{
    write::{AssignedIds, Batch, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, Store, Stores, ValueKey,
};

pub struct SQLReadReplica {
    primary: Store,
    replicas: Vec<Store>,
    last_used_replica: AtomicUsize,
}

impl SQLReadReplica {
    pub async fn open(
        config: &mut Config,
        prefix: impl AsKey,
        stores: &Stores,
        create_tables: bool,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let primary_id = config.value_require((&prefix, "primary"))?.to_string();
        let replica_ids = config
            .values((&prefix, "replicas"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();

        let primary = if let Some(store) = stores.stores.get(&primary_id) {
            if store.is_pg_or_mysql() {
                store.clone()
            } else {
                config.new_build_error(
                    (&prefix, "primary"),
                    "Primary store must be a PostgreSQL or MySQL store",
                );
                return None;
            }
        } else {
            config.new_build_error(
                (&prefix, "primary"),
                format!("Primary store {primary_id} not found"),
            );
            return None;
        };
        let mut replicas = Vec::with_capacity(replica_ids.len());
        for replica_id in replica_ids {
            if let Some(store) = stores.stores.get(&replica_id) {
                if store.is_pg_or_mysql() {
                    replicas.push(store.clone());
                } else {
                    config.new_build_error(
                        (&prefix, "replicas"),
                        "Replica store must be a PostgreSQL or MySQL store",
                    );
                    return None;
                }
            } else {
                config.new_build_error(
                    (&prefix, "replicas"),
                    format!("Replica store {replica_id} not found"),
                );
                return None;
            }
        }
        if !replicas.is_empty() {
            if create_tables {
                let result = match &primary {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.create_tables().await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.create_tables().await,
                    _ => panic!("Invalid store type"),
                };

                if let Err(err) = result {
                    config.new_build_error(
                        (&prefix, "primary"),
                        format!("Failed to create tables: {err}"),
                    );
                }
            }

            Some(Self {
                primary,
                replicas,
                last_used_replica: AtomicUsize::new(0),
            })
        } else {
            config.new_build_error((&prefix, "replicas"), "No replica stores specified");
            None
        }
    }

    async fn run_op<'x, F, T, R>(&'x self, f: F) -> trc::Result<T>
    where
        F: Fn(&'x Store) -> R,
        R: Future<Output = trc::Result<T>>,
        T: 'static,
    {
        let mut last_error = None;
        for store in [
            &self.replicas
                [self.last_used_replica.fetch_add(1, Ordering::Relaxed) % self.replicas.len()],
            &self.primary,
        ] {
            match f(store).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if err.is_assertion_failure() {
                        return Err(err);
                    } else {
                        last_error = Some(err);
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        self.run_op(move |store| {
            let range = range.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_blob(key, range).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_blob(key, range).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.put_blob(key, data).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.delete_blob(key).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        self.run_op(move |store| {
            let key = key.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_value(key).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_value(key).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn get_bitmap(
        &self,
        key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        self.run_op(move |store| {
            let key = key.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_bitmap(key).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_bitmap(key).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let mut last_error = None;
        for store in [
            &self.replicas
                [self.last_used_replica.fetch_add(1, Ordering::Relaxed) % self.replicas.len()],
            &self.primary,
        ] {
            match match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.iterate(params.clone(), &mut cb).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.iterate(params.clone(), &mut cb).await,
                _ => panic!("Invalid store type"),
            } {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap())
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        self.run_op(move |store| {
            let key = key.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_counter(key).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_counter(key).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.write(batch).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.write(batch).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.delete_range(from, to).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.purge_store().await,
            _ => panic!("Invalid store type"),
        }
    }
}
