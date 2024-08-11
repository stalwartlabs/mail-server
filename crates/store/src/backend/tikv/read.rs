/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use std::ops::Bound;
use tikv_client::{BoundRange, Key as TikvKey, KvPair, Snapshot, Transaction, TransactionOptions, Value};
use futures::TryStreamExt;
use roaring::RoaringBitmap;
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE,
};

use super::{into_error, MAX_KEY_SIZE, MAX_SCAN_KEYS_SIZE, MAX_SCAN_VALUES_SIZE, MAX_VALUE_SIZE, TikvStore};

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(Value),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

impl TikvStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        todo!()
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

        if let Some(bytes) = self
            .snapshot_trx()
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
            .begin_pessimistic()
            .await
            .map_err(into_error)
    }

    pub(crate) async fn snapshot_trx(&self) -> trc::Result<Snapshot> {
        let read_trx = self.read_trx().await?;

        Ok(Snapshot::new(read_trx))
    }

    pub(super) async fn read_chunked_value<ReadTrx: ReadTransaction>(
        &self,
        key: &[u8],
        trx: &mut ReadTrx
    ) -> trc::Result<ChunkedValue> {
        if let Some(mut bytes) = trx.get(key.to_vec()).await? {
            if bytes.len() < MAX_VALUE_SIZE as usize {
                Ok(ChunkedValue::Single(bytes))
            } else {
                let mut value = Vec::with_capacity(bytes.len() * 2);
                value.append(&mut bytes);
                let mut n_chunks = 1;

                let mut first = Bound::Included(TikvKey::from(self.new_key_serializer(key.len() + 1, false)
                    .write(key)
                    .write(0u8)
                    .finalize()));

                'outer: loop {
                    // Maybe use the last byte of the last key?
                    let mut count = 0;

                    let last = Bound::Included(TikvKey::from(self.new_key_serializer(key.len() + 1, false)
                        .write(key)
                        .write(u8::MAX)
                        .finalize()));

                    let bound_range = BoundRange::new(first, last);

                    let mut kv_pair_iter = trx.scan(bound_range, MAX_SCAN_VALUES_SIZE)
                        .await?
                        .peekable();

                    while let Some(kv_pair) = kv_pair_iter.next() {
                        let (key, mut kv_value) = kv_pair.into();
                        value.append(&mut kv_value);
                        count += 1;
                        if kv_pair_iter.peek().is_none() {
                            n_chunks += count;
                            if count < MAX_KEY_SIZE {
                                break 'outer;
                            }
                            first = Bound::Excluded(key);
                            continue 'outer;
                        }
                    }

                    // Empty
                    break;
                }

                Ok(ChunkedValue::Chunked {
                    bytes: value,
                    n_chunks: *key.last().unwrap(),
                })
            }
        } else {
            Ok(ChunkedValue::None)
        }
    }

}

pub(crate) trait ReadTransaction {
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