/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;

use super::{into_error, EtcdStore};

use crate::{
    backend::deserialize_i64_le,
    write::{BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey
};

impl EtcdStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let key_subspace: u8 = key.subspace();
        let key = key.serialize(0);

        let mut client = self.get_prefix_client(key_subspace);

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

        let begin = params.begin;
        let key_subspace: u8 = begin.subspace();
        let begin: Vec<u8> = begin.serialize(0);
        let end: Vec<u8> = params.end.serialize(0);
        // TODO: implement params.ascending

        let mut client = self.get_prefix_client(key_subspace);
        let resp = client.get(begin.clone(), None)
            .await
            .map_err(into_error)?;
        for kv in resp.kvs() {
            let key = &kv.key();
            let value = &kv.value();
            if key.as_ref() < begin.as_slice()
                || key.as_ref() > end.as_slice()
                || !cb(&key, &value)?
                || params.first
            {
                break;
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {

        let key = key.into();
        let key_subspace: u8 = key.subspace();
        let key: Vec<u8> = key.serialize(0);

        let mut client = self.get_prefix_client(key_subspace);
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
