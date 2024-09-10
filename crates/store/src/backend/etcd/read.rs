/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;

use super::{into_error, EtcdStore};

use crate::{
    backend::deserialize_i64_le,
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE
};

impl EtcdStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let key = key.serialize(WITH_SUBSPACE);

        // Clone clients tey said: https://github.com/etcdv3/etcd-client/issues/17
        let mut client = self.client.clone();
        let resp = client.get(key, None)
            .await
            .map_err(into_error)?;
        if let Some(kv) = resp.kvs().first() {
            U::deserialize(&kv.value()).map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        todo!()
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        todo!()
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {

        let key = key.into().serialize(WITH_SUBSPACE);

        // Clone clients tey said: https://github.com/etcdv3/etcd-client/issues/17
        let mut client = self.client.clone();
        let resp = client.get(key.clone(), None)
            .await
            .map_err(into_error)?;
        if let Some(kv) = resp.kvs().first() {
            deserialize_i64_le(&key, &kv.value())
        } else {
            Ok(0)
        }
    }
}
