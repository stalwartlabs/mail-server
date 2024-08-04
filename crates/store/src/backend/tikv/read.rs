/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use bincode::Options;
use tikv_client::{Key as TikvKey, Snapshot, Transaction, TransactionOptions, Value};
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

use super::{into_error, MAX_KEYS, MAX_KV_PAIRS, MAX_VALUE_SIZE, ReadTransaction, TikvStore};

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
        let key = key.serialize(WITH_SUBSPACE);
        let mut ss = self.snapshot_trx().await?;

        match read_chunked_value_snapshot(&key, &mut ss).await? {
            ChunkedValue::Single(bytes) => U::deserialize(&bytes).map(Some),
            ChunkedValue::Chunked { bytes, .. } => U::deserialize(&bytes).map(Some),
            ChunkedValue::None => Ok(None),
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
        let mut begin: TikvKey = params.begin.serialize(WITH_SUBSPACE).into();
        let end: TikvKey = params.end.serialize(WITH_SUBSPACE).into();

        if !params.first {
            let mut trx = self.snapshot_trx().await?;
            loop {
                let mut values = trx
                    .scan((begin.clone(), end.clone()), MAX_KV_PAIRS)
                    .await
                    .map_err(into_error)?;

                let mut last_key: TikvKey = begin.clone();

                let mut total_kv_pairs = 0;

                while let Some(kv_pair) = values.next() {
                    total_kv_pairs += 1;
                    // Costly
                    last_key = kv_pair.key().clone();
                    let key: &[u8] = kv_pair.key().into();
                    let value: &[u8] = kv_pair.key().into();

                    cb(key.get(1..).unwrap_or_default(), value)?;
                }

                if total_kv_pairs != MAX_KV_PAIRS {
                    begin = last_key;
                    break;
                }
            }
        } else {
            let mut trx = self.snapshot_trx().await?;
            let mut values = trx
                .scan((begin, end), 1)
                .await
                .map_err(into_error)?;

            if let Some(kv_pair) = values.next() {
                let key: &[u8] = kv_pair.key().into();
                let value: &[u8] = kv_pair.key().into();

                cb(key.get(1..).unwrap_or_default(), value)?;
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
        todo!()
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        self.trx_client
            .begin_optimistic()
            .await
            .map_err(into_error)
    }

    pub(crate) async fn snapshot_trx(&self) -> trc::Result<Snapshot> {
        let timestamp = self.trx_client
            .current_timestamp()
            .await
            .map_err(into_error)?;

        Ok(self.trx_client.snapshot(timestamp, TransactionOptions::new_optimistic()))
    }
}

// TODO: Figure out a way to deduplicate the code
pub(crate) async fn read_chunked_value_snapshot(
    key: &[u8],
    ss: &mut Snapshot
) -> trc::Result<ChunkedValue> {
    // TODO: Costly, redo
    if let Some(bytes) = ss.get(key.to_vec()).await.map_err(into_error)? {
        if bytes.len() < MAX_VALUE_SIZE {
            Ok(ChunkedValue::Single(bytes))
        } else {
            let mut value = Vec::with_capacity(bytes.len() * 2);
            value.extend_from_slice(&bytes);
            let mut key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(0u8)
                .finalize();

            // TODO: Costly, redo
            while let Some(bytes) = ss.get(key.to_vec()).await.map_err(into_error)? {
                value.extend_from_slice(&bytes);
                *key.last_mut().unwrap() += 1;
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

// TODO: Figure out a way to deduplicate the code
pub(crate) async fn read_chunked_value_transaction(
    key: &[u8],
    trx: &mut Transaction
) -> trc::Result<ChunkedValue> {
    // TODO: Costly, redo
    if let Some(bytes) = trx.get(key.to_vec()).await.map_err(into_error)? {
        if bytes.len() < MAX_VALUE_SIZE {
            Ok(ChunkedValue::Single(bytes))
        } else {
            let mut value = Vec::with_capacity(bytes.len() * 2);
            value.extend_from_slice(&bytes);
            let mut key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(0u8)
                .finalize();

            // TODO: Costly, redo
            while let Some(bytes) = trx.get(key.to_vec()).await.map_err(into_error)? {
                value.extend_from_slice(&bytes);
                *key.last_mut().unwrap() += 1;
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