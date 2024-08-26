/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use std::ops::Bound;
use tikv_client::{BoundRange, CheckLevel, Key as TikvKey, KvPair, Snapshot, Transaction, Value};
use roaring::RoaringBitmap;
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE,
};
use crate::backend::tikv::read::chunking::get_chunked_value;
use super::{into_error, MAX_KEY_SIZE, MAX_SCAN_KEYS_SIZE, MAX_SCAN_VALUES_SIZE, MAX_VALUE_SIZE, TikvStore};

impl TikvStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let mut snapshot = self.snapshot_read().await?;

        match get_chunked_value(&key, &mut snapshot).await? {
            Some(bytes) => U::deserialize(&bytes).map(Some),
            None => Ok(None)
        }
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let mut trx = self.snapshot_read().await?;
        let mut bm = RoaringBitmap::new();

        let mut begin = key.serialize(WITH_SUBSPACE);
        key.document_id = u32::MAX;
        let mut end = key.serialize(WITH_SUBSPACE);
        end.push(u8::MIN); // Inclusive
        let key_len = begin.len();

        'outer: loop {
            let keys = trx
                .scan_keys((begin, end.clone()), MAX_SCAN_KEYS_SIZE)
                .await
                .map_err(into_error)?;

            let mut count = 0;
            let mut last_key = None;

            for key in keys {
                count += 1;
                let key_slice: &[u8] = key.as_ref().into();
                if key.len() == key_len {
                    bm.insert(key_slice.deserialize_be_u32(key.len() - U32_LEN)?);
                }
                last_key = Some(key)
            }

            if count == MAX_SCAN_KEYS_SIZE {
                // Guaranteed to have a key unless MAX_SCAN_KEYS_SIZE is 0
                begin = last_key.unwrap().into();
                begin.push(u8::MIN); // To make the start range exclusive
                continue;
            } else {
                break;
            }
        }

        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let mut begin = params.begin.serialize(WITH_SUBSPACE);
        let mut end = params.end.serialize(WITH_SUBSPACE);
        end.push(u8::MIN); // Inclusive

        let mut trx = self.snapshot_read().await?;

        if !params.first {
            if params.ascending {
                loop {
                    let keys = trx
                        .scan((begin, end.clone()), MAX_SCAN_VALUES_SIZE)
                        .await
                        .map_err(into_error)?;

                    let mut count = 0;
                    let mut last_key = None;
                    for kv_pair in keys {
                        count += 1;
                        let key_slice: &[u8] = kv_pair.key().into();
                        let value = kv_pair.value().as_slice();

                        if !cb(key_slice.get(1..).unwrap_or_default(), value)? {
                            return Ok(());
                        }

                        last_key = Some(kv_pair.into_key());
                    }

                    if count == MAX_SCAN_VALUES_SIZE {
                        begin = last_key.unwrap().into();
                        begin.push(u8::MIN);
                        continue;
                    } else {
                        break;
                    }
                }
            } else {
                loop {
                    let keys = trx
                        .scan_reverse((begin.clone(), end), MAX_SCAN_VALUES_SIZE)
                        .await
                        .map_err(into_error)?;

                    let mut count = 0;
                    let mut last_key = None;
                    for kv_pair in keys {
                        count += 1;
                        let key_slice: &[u8] = kv_pair.key().into();
                        let value = kv_pair.value().as_slice();

                        if !cb(key_slice.get(1..).unwrap_or_default(), value)? {
                            return Ok(());
                        }

                        last_key = Some(kv_pair.into_key());
                    }

                    if count == MAX_SCAN_VALUES_SIZE {
                        end = last_key.unwrap().into();
                        continue;
                    } else {
                        break;
                    }
                }
            }
        } else {
            let result = if params.ascending {
                trx.scan((begin, end), 1)
                    .await
                    .map_err(into_error)?
                    .next()
            } else {
                trx.scan_reverse((begin, end), 1)
                    .await
                    .map_err(into_error)?
                    .next()
            };

            if let Some(kv_pair) = result {
                let key: &[u8] = kv_pair.key().into();
                let value = kv_pair.value().as_slice();
                cb(key.get(1..).unwrap_or_default(), value)?;
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);

        if let Some(bytes) = self
            .snapshot_read()
            .await?
            .get(key.clone())
            .await
            .map_err(into_error)?
        {
            deserialize_i64_le(&key, &bytes)
        } else {
            Ok(0)
        }
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        self.trx_client
            .begin_with_options(self.read_trx_options.clone())
            .await
            .map_err(into_error)
    }

    pub(crate) async fn snapshot_read(&self) -> trc::Result<Snapshot> {
        let current_timestamp = self
            .trx_client
            .current_timestamp()
            .await
            .map_err(into_error)?;

        Ok(self.trx_client.snapshot(current_timestamp, self.read_trx_options.clone()))
    }

}

pub(super) mod chunking {
    use super::*;

    pub(in super::super) async fn get_chunked_value<ReadTrx: ReadTransaction>(
        key: &[u8],
        trx: &mut ReadTrx
    ) -> trc::Result<Option<Vec<u8>>> {
        let Some(mut bytes) = trx.get(key.to_vec()).await? else {
            return Ok(None);
        };

        if bytes.len() != MAX_VALUE_SIZE {
            return Ok(Some(bytes))
        }

        let start_key = KeySerializer::new(key.len() + 1)
            .write(key)
            .write(u8::MIN)
            .finalize();
        let end_key = KeySerializer::new(key.len() + 2)
            .write(key)
            .write(u8::MAX)
            .write(u8::MIN) // Null byte to make the end inclusive
            .finalize();

        let mut keys: Vec<tikv_client::Key> = trx
            .scan_keys((start_key, end_key), 256 + 1)
            .await?
            .collect();

        for chunk_key in keys {
            // Any scanned keys are guaranteed to have a value
            let mut value = trx.get(chunk_key).await?.unwrap();
            bytes.append(&mut value);
        }

        Ok(Some(bytes))
    }

    trait ReadTransaction {
        async fn get(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<Option<Value>>;
        async fn key_exists(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<bool>;
        async fn batch_get(
            &mut self,
            keys: impl IntoIterator<Item = impl Into<tikv_client::Key>>
        ) -> trc::Result<impl Iterator<Item = KvPair>>;
        async fn scan(
            &mut self,
            range: impl Into<BoundRange>,
            limit: u32
        ) -> trc::Result<impl Iterator<Item = KvPair>>;
        async fn scan_keys(
            &mut self,
            range: impl Into<BoundRange>,
            limit: u32
        ) -> trc::Result<impl Iterator<Item =tikv_client::Key>>;
        async fn scan_reverse(
            &mut self,
            range: impl Into<BoundRange>,
            limit: u32
        ) -> trc::Result<impl Iterator<Item = KvPair>>;
        async fn scan_keys_reverse(
            &mut self,
            range: impl Into<BoundRange>,
            limit: u32
        ) -> trc::Result<impl Iterator<Item =tikv_client::Key>>;
    }

    impl ReadTransaction for Transaction {
        async fn get(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<Option<Value>> {
            self.get(key).await.map_err(into_error)
        }

        async fn key_exists(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<bool> {
            self.key_exists(key).await.map_err(into_error)
        }

        async fn batch_get(&mut self, keys: impl IntoIterator<Item=impl Into<tikv_client::Key>>) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.batch_get(keys).await.map_err(into_error)
        }

        async fn scan(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.scan(range, limit).await.map_err(into_error)
        }

        async fn scan_keys(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=tikv_client::Key>> {
            self.scan_keys(range, limit).await.map_err(into_error)
        }

        async fn scan_reverse(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.scan_reverse(range, limit).await.map_err(into_error)
        }

        async fn scan_keys_reverse(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=tikv_client::Key>> {
            self.scan_keys_reverse(range, limit).await.map_err(into_error)
        }
    }

    impl ReadTransaction for Snapshot {
        async fn get(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<Option<Value>> {
            self.get(key).await.map_err(into_error)
        }

        async fn key_exists(&mut self, key: impl Into<tikv_client::Key>) -> trc::Result<bool> {
            self.key_exists(key).await.map_err(into_error)
        }

        async fn batch_get(&mut self, keys: impl IntoIterator<Item=impl Into<tikv_client::Key>>) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.batch_get(keys).await.map_err(into_error)
        }

        async fn scan(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.scan(range, limit).await.map_err(into_error)
        }

        async fn scan_keys(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=tikv_client::Key>> {
            self.scan_keys(range, limit).await.map_err(into_error)
        }

        async fn scan_reverse(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=KvPair>> {
            self.scan_reverse(range, limit).await.map_err(into_error)
        }

        async fn scan_keys_reverse(&mut self, range: impl Into<BoundRange>, limit: u32) -> trc::Result<impl Iterator<Item=tikv_client::Key>> {
            self.scan_keys_reverse(range, limit).await.map_err(into_error)
        }
    }
}