/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FdbStore, MAX_VALUE_SIZE, ReadVersion, into_error};
use crate::{
    BitmapKey, Deserialize, IterateParams, Key, U32_LEN, ValueKey, WITH_SUBSPACE,
    backend::deserialize_i64_le,
    write::{
        BitmapClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use foundationdb::{
    KeySelector, RangeOption, Transaction,
    future::FdbSlice,
    options::{self, StreamingMode},
};
use futures::TryStreamExt;
use roaring::RoaringBitmap;

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(FdbSlice),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

impl FdbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(WITH_SUBSPACE);
        let trx = self.read_trx().await?;

        match read_chunked_value(&key, &trx, true).await? {
            ChunkedValue::Single(bytes) => U::deserialize(&bytes).map(Some),
            ChunkedValue::Chunked { bytes, .. } => U::deserialize_owned(bytes).map(Some),
            ChunkedValue::None => Ok(None),
        }
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass>,
    ) -> trc::Result<Option<RoaringBitmap>> {
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

        while let Some(value) = values.try_next().await.map_err(into_error)? {
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
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let begin = params.begin.serialize(WITH_SUBSPACE);
        let end = params.end.serialize(WITH_SUBSPACE);

        if !params.first {
            let mut last_key = vec![];

            'outer: loop {
                let begin_selector = if last_key.is_empty() {
                    KeySelector::first_greater_or_equal(&begin)
                } else {
                    KeySelector::first_greater_than(&last_key)
                };

                let trx = self.read_trx().await?;
                let mut values = trx.get_ranges(
                    RangeOption {
                        begin: begin_selector,
                        end: KeySelector::first_greater_than(&end),
                        mode: options::StreamingMode::WantAll,
                        reverse: !params.ascending,
                        ..Default::default()
                    },
                    true,
                );

                let mut last_key_ = vec![];
                loop {
                    match values.try_next().await {
                        Ok(Some(values)) => {
                            let mut key = &[] as &[u8];
                            for value in values.iter() {
                                key = value.key();
                                if !cb(key.get(1..).unwrap_or_default(), value.value())? {
                                    return Ok(());
                                }
                            }
                            if values.more() {
                                last_key_ = key.to_vec();
                            }
                        }
                        Ok(None) => {
                            break 'outer;
                        }
                        Err(e) => {
                            if e.code() == 1007 && !last_key_.is_empty() {
                                // Transaction is too old to perform reads or be committed
                                drop(values);
                                last_key = last_key_;
                                continue 'outer;
                            } else {
                                return Err(into_error(e));
                            }
                        }
                    }
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

            if let Some(value) = values.try_next().await.map_err(into_error)? {
                cb(value.key().get(1..).unwrap_or_default(), value.value())?;
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);
        if let Some(bytes) = self
            .read_trx()
            .await?
            .get(&key, true)
            .await
            .map_err(into_error)?
        {
            deserialize_i64_le(&key, &bytes)
        } else {
            Ok(0)
        }
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        let (is_expired, mut read_version) = {
            let version = self.version.lock();
            (version.is_expired(), version.version)
        };
        let trx = self.db.create_trx().map_err(into_error)?;

        if is_expired {
            read_version = trx.get_read_version().await.map_err(into_error)?;
            *self.version.lock() = ReadVersion::new(read_version);
        } else {
            trx.set_read_version(read_version);
        }

        Ok(trx)
    }
}

pub(crate) async fn read_chunked_value(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> trc::Result<ChunkedValue> {
    if let Some(bytes) = trx.get(key, snapshot).await.map_err(into_error)? {
        if bytes.len() < MAX_VALUE_SIZE {
            Ok(ChunkedValue::Single(bytes))
        } else {
            let mut value = Vec::with_capacity(bytes.len() * 2);
            value.extend_from_slice(&bytes);
            let mut key = KeySerializer::new(key.len() + 1)
                .write(key)
                .write(0u8)
                .finalize();

            while let Some(bytes) = trx.get(&key, snapshot).await.map_err(into_error)? {
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
