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
    pub fn open(config: &mut Config, prefix: impl AsKey, stores: &Stores) -> Option<Self> {
        let prefix = prefix.as_key();
        let primary_id = config.value_require((&prefix, "primary"))?.to_string();
        let replica_ids = config
            .values((&prefix, "replicas"))
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>();

        let primary = if let Some(store) = stores.stores.get(&primary_id) {
            store.clone()
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
                replicas.push(store.clone());
            } else {
                config.new_build_error(
                    (&prefix, "replicas"),
                    format!("Replica store {replica_id} not found"),
                );
                return None;
            }
        }
        if !replicas.is_empty() {
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

    #[inline(always)]
    fn replica(&self) -> &Store {
        &self.replicas[self.last_used_replica.fetch_add(1, Ordering::Relaxed) % self.replicas.len()]
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        Box::pin(self.replica().get_blob(key, range)).await
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        Box::pin(self.primary.put_blob(key, data)).await
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        Box::pin(self.primary.delete_blob(key)).await
    }

    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        Box::pin(self.replica().get_value(key)).await
    }

    pub async fn get_bitmap(
        &self,
        key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        Box::pin(self.replica().get_bitmap(key)).await
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        Box::pin(self.replica().iterate(params, cb)).await
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
        Box::pin(self.replica().get_counter(key)).await
    }

    pub async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        Box::pin(self.primary.write(batch)).await
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        Box::pin(self.primary.delete_range(from, to)).await
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        Box::pin(self.primary.purge_store()).await
    }
}
