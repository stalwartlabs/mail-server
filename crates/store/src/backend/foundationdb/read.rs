/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use foundationdb::{
    future::FdbSlice,
    options::{self, StreamingMode},
    KeySelector, RangeOption, Transaction,
};
use futures::StreamExt;
use roaring::RoaringBitmap;

use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE,
};

use super::{FdbStore, MAX_VALUE_SIZE};

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
        let trx = self.db.create_trx()?;

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
        let trx = self.db.create_trx()?;
        let mut values = trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(begin),
                end: KeySelector::first_greater_or_equal(end),
                mode: StreamingMode::WantAll,
                reverse: false,
                ..RangeOption::default()
            },
            true,
        );

        while let Some(values) = values.next().await {
            for value in values? {
                let key = value.key();
                if key.len() == key_len {
                    bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                }
            }
        }

        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let begin = params.begin.serialize(WITH_SUBSPACE);
        let end = params.end.serialize(WITH_SUBSPACE);

        let trx = self.db.create_trx()?;
        let mut iter = trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&begin),
                end: KeySelector::first_greater_than(&end),
                mode: if params.first {
                    options::StreamingMode::Small
                } else {
                    options::StreamingMode::Iterator
                },
                reverse: !params.ascending,
                ..Default::default()
            },
            true,
        );

        while let Some(values) = iter.next().await {
            for value in values? {
                let key = value.key().get(1..).unwrap_or_default();
                let value = value.value();

                if !cb(key, value)? || params.first {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(WITH_SUBSPACE);
        if let Some(bytes) = self.db.create_trx()?.get(&key, true).await? {
            deserialize_i64_le(&bytes)
        } else {
            Ok(0)
        }
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

#[cfg(feature = "fdb-chunked-bm")]
pub(crate) async fn read_chunked_bitmap(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> crate::Result<ChunkedBitmap> {
    match read_chunked_value(key, trx, snapshot).await? {
        ChunkedValue::Single(bytes) => RoaringBitmap::deserialize_unchecked_from(bytes.as_ref())
            .map(ChunkedBitmap::Single)
            .map_err(|e| {
                crate::Error::InternalError(format!("Failed to deserialize bitmap: {}", e))
            }),
        ChunkedValue::Chunked { bytes, n_chunks } => {
            RoaringBitmap::deserialize_unchecked_from(bytes.as_slice())
                .map(|bitmap| ChunkedBitmap::Chunked { n_chunks, bitmap })
                .map_err(|e| {
                    crate::Error::InternalError(format!("Failed to deserialize bitmap: {}", e))
                })
        }
        ChunkedValue::None => Ok(ChunkedBitmap::None),
    }
}

#[cfg(feature = "fdb-chunked-bm")]
impl From<ChunkedBitmap> for Option<RoaringBitmap> {
    fn from(bitmap: ChunkedBitmap) -> Self {
        match bitmap {
            ChunkedBitmap::Single(bitmap) => Some(bitmap),
            ChunkedBitmap::Chunked { bitmap, .. } => Some(bitmap),
            ChunkedBitmap::None => None,
        }
    }
}
