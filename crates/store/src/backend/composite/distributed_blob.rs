/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::ops::Range;

use utils::config::{utils::AsKey, Config};

use crate::{BlobBackend, Store, Stores};

pub struct DistributedBlob {
    pub stores: Vec<BlobBackend>,
}

impl DistributedBlob {
    pub fn open(config: &mut Config, prefix: impl AsKey, stores: &Stores) -> Option<Self> {
        let prefix = prefix.as_key();
        let store_ids = config
            .values((&prefix, "stores"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();

        let mut blob_stores = Vec::with_capacity(store_ids.len());
        for store_id in store_ids {
            if let Some(store) = stores.blob_stores.get(&store_id) {
                blob_stores.push(store.backend.clone());
            } else {
                config.new_build_error(
                    (&prefix, "stores"),
                    format!("Blob store {store_id} not found"),
                );
                return None;
            }
        }
        if !blob_stores.is_empty() {
            Some(Self {
                stores: blob_stores,
            })
        } else {
            config.new_build_error((&prefix, "stores"), "No blob stores specified");
            None
        }
    }

    #[inline(always)]
    fn get_store(&self, key: &[u8]) -> &BlobBackend {
        &self.stores[key.first().copied().unwrap_or_default() as usize % self.stores.len()]
    }

    pub async fn get_blob(
        &self,
        key: &[u8],
        read_range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        Box::pin(async move {
            match self.get_store(key) {
                BlobBackend::Store(store) => match store {
                    #[cfg(feature = "sqlite")]
                    Store::SQLite(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "foundation")]
                    Store::FoundationDb(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_blob(key, read_range).await,
                    #[cfg(feature = "rocks")]
                    Store::RocksDb(store) => store.get_blob(key, read_range).await,
                    Store::SQLReadReplica(store) => store.get_blob(key, read_range).await,
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobBackend::Fs(store) => store.get_blob(key, read_range).await,
                #[cfg(feature = "s3")]
                BlobBackend::S3(store) => store.get_blob(key, read_range).await,
                BlobBackend::Composite(_) => unimplemented!(),
            }
        })
        .await
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        Box::pin(async move {
            match self.get_store(key) {
                BlobBackend::Store(store) => match store {
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
                    Store::SQLReadReplica(store) => store.put_blob(key, data).await,
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobBackend::Fs(store) => store.put_blob(key, data).await,
                #[cfg(feature = "s3")]
                BlobBackend::S3(store) => store.put_blob(key, data).await,
                BlobBackend::Composite(_) => unimplemented!(),
            }
        })
        .await
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        Box::pin(async move {
            match self.get_store(key) {
                BlobBackend::Store(store) => match store {
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
                    Store::SQLReadReplica(store) => store.delete_blob(key).await,
                    Store::None => Err(trc::StoreEvent::NotConfigured.into()),
                },
                BlobBackend::Fs(store) => store.delete_blob(key).await,
                #[cfg(feature = "s3")]
                BlobBackend::S3(store) => store.delete_blob(key).await,
                BlobBackend::Composite(_) => unimplemented!(),
            }
        })
        .await
    }
}
