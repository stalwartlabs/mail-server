/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use foundationdb::{
    future::FdbSlice,
    options::{self, StreamingMode},
    KeySelector, RangeOption, Transaction,
};
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

use super::{FdbStore, ReadVersion, TimedTransaction, MAX_VALUE_SIZE};

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(FdbSlice),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

impl FdbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let trx = self.read_trx().await?;

        match read_chunked_value(&key, &trx, true).await? {
            ChunkedValue::Single(bytes) => U::deserialize(&bytes).map(Some),
            ChunkedValue::Chunked { bytes, .. } => U::deserialize(&bytes).map(Some),
            ChunkedValue::None => Ok(None),
        }
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();
        let begin = key.serialize(WITH_SUBSPACE);
        key.document_id = u32::MAX;
        let end = key.serialize(WITH_SUBSPACE);
        let key_len = begin.len();
        let trx = self.read_trx().await?;
        let mut values = trx.get_ranges_keyvalues(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(begin),
                end: KeySelector::first_greater_or_equal(end),
                mode: StreamingMode::WantAll,
                reverse: false,
                ..RangeOption::default()
            },
            true,
        );

        while let Some(value) = values.try_next().await? {
            let key = value.key();
            if key.len() == key_len {
                bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
            }
        }

        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let mut begin = params.begin.serialize(WITH_SUBSPACE);
        let end = params.end.serialize(WITH_SUBSPACE);

        if !params.first {
            let mut begin_selector = KeySelector::first_greater_or_equal(&begin);

            loop {
                let mut last_key_bytes = None;

                {
                    let trx = self.timed_read_trx().await?;
                    let mut values = trx.as_ref().get_ranges(
                        RangeOption {
                            begin: begin_selector,
                            end: KeySelector::first_greater_than(&end),
                            mode: options::StreamingMode::WantAll,
                            reverse: !params.ascending,
                            ..Default::default()
                        },
                        true,
                    );

                    while let Some(values) = values.try_next().await? {
                        let mut last_key = &[] as &[u8];

                        for value in values.iter() {
                            last_key = value.key();
                            if !cb(last_key.get(1..).unwrap_or_default(), value.value())? {
                                return Ok(());
                            }
                        }

                        if values.more() && trx.is_expired() {
                            last_key_bytes = last_key.to_vec().into();
                            break;
                        }
                    }
                }

                if let Some(last_key_bytes) = last_key_bytes {
                    begin = last_key_bytes;
                    begin_selector = KeySelector::first_greater_than(&begin);
                } else {
                    break;
                }
            }
        } else {
            let trx = self.read_trx().await?;
            let mut values = trx.get_ranges_keyvalues(
                RangeOption {
                    begin: KeySelector::first_greater_or_equal(&begin),
                    end: KeySelector::first_greater_than(&end),
                    mode: options::StreamingMode::Small,
                    reverse: !params.ascending,
                    ..Default::default()
                },
                true,
            );

            if let Some(value) = values.try_next().await? {
                cb(value.key().get(1..).unwrap_or_default(), value.value())?;
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);
        if let Some(bytes) = self.read_trx().await?.get(&key, true).await? {
            deserialize_i64_le(&bytes)
        } else {
            Ok(0)
        }
    }

    pub(crate) async fn read_trx(&self) -> crate::Result<Transaction> {
        let (is_expired, mut read_version) = {
            let version = self.version.lock();
            (version.is_expired(), version.version)
        };
        let trx = self.db.create_trx()?;

        if is_expired {
            read_version = trx.get_read_version().await?;
            *self.version.lock() = ReadVersion::new(read_version);
        } else {
            trx.set_read_version(read_version);
        }

        Ok(trx)
    }

    pub(crate) async fn timed_read_trx(&self) -> crate::Result<TimedTransaction> {
        self.db
            .create_trx()
            .map_err(Into::into)
            .map(TimedTransaction::new)
    }
}

pub(crate) async fn read_chunked_value(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> crate::Result<ChunkedValue> {
    if let Some(bytes) = trx.get(key, snapshot).await? {
        if bytes.len() < MAX_VALUE_SIZE {
            Ok(ChunkedValue::Single(bytes))
        } else {
            let mut value = Vec::with_capacity(bytes.len() * 2);
            value.extend_from_slice(&bytes);
            let mut key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(0u8)
                .finalize();

            while let Some(bytes) = trx.get(&key, snapshot).await? {
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
