/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use utils::config::{Config, utils::AsKey};

use crate::{
    Deserialize, InMemoryStore, Stores, Value,
    dispatch::lookup::{KeyValue, LookupKey},
};

#[derive(Debug)]
pub struct ShardedInMemory {
    pub stores: Vec<InMemoryStore>,
}

impl ShardedInMemory {
    pub fn open(config: &mut Config, prefix: impl AsKey, stores: &Stores) -> Option<Self> {
        let prefix = prefix.as_key();
        let store_ids = config
            .values((&prefix, "stores"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();

        let mut in_memory_stores = Vec::with_capacity(store_ids.len());
        for store_id in store_ids {
            if let Some(store) = stores
                .in_memory_stores
                .get(&store_id)
                .filter(|store| store.is_redis())
            {
                in_memory_stores.push(store.clone());
            } else {
                config.new_build_error(
                    (&prefix, "stores"),
                    format!("In-memory store {store_id} not found"),
                );
                return None;
            }
        }
        if !in_memory_stores.is_empty() {
            Some(Self {
                stores: in_memory_stores,
            })
        } else {
            config.new_build_error((&prefix, "stores"), "No in-memory stores specified");
            None
        }
    }

    #[inline(always)]
    fn get_store(&self, key: &[u8]) -> &InMemoryStore {
        &self.stores[xxhash_rust::xxh3::xxh3_64(key) as usize % self.stores.len()]
    }

    pub async fn key_set(&self, kv: KeyValue<Vec<u8>>) -> trc::Result<()> {
        Box::pin(async move {
            match self.get_store(&kv.key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_set(&kv.key, &kv.value, kv.expires).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_incr(&self, kv: KeyValue<i64>) -> trc::Result<i64> {
        Box::pin(async move {
            match self.get_store(&kv.key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_incr(&kv.key, kv.value, kv.expires).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn key_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_delete(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_delete(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<()> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_delete(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    #[allow(unused_variables)]
    pub async fn key_delete_prefix(&self, prefix: &[u8]) -> trc::Result<()> {
        Box::pin(async move {
            #[cfg(feature = "redis")]
            for store in &self.stores {
                match store {
                    InMemoryStore::Redis(store) => store.key_delete_prefix(prefix).await?,
                    InMemoryStore::Static(_) => {
                        return Err(trc::StoreEvent::NotSupported.into_err());
                    }
                    _ => return Err(trc::StoreEvent::NotSupported.into_err()),
                }
            }

            Ok(())
        })
        .await
    }

    pub async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
        &self,
        key: impl Into<LookupKey<'_>>,
    ) -> trc::Result<Option<T>> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_get(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn counter_get(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<i64> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.counter_get(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }

    pub async fn key_exists(&self, key: impl Into<LookupKey<'_>>) -> trc::Result<bool> {
        let key_ = key.into();
        let key = key_.as_bytes();
        Box::pin(async move {
            match self.get_store(key) {
                #[cfg(feature = "redis")]
                InMemoryStore::Redis(store) => store.key_exists(key).await,
                InMemoryStore::Static(_) => Err(trc::StoreEvent::NotSupported.into_err()),
                _ => Err(trc::StoreEvent::NotSupported.into_err()),
            }
        })
        .await
    }
}
