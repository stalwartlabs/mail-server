/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;
use rocksdb::{Direction, IteratorMode};

use super::RocksDbStore;

use crate::{
    backend::rocksdb::CfHandle,
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN,
};

impl RocksDbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(
                &db.cf_handle(std::str::from_utf8(&[key.subspace()]).unwrap())
                    .unwrap(),
                &key.serialize(0),
            )
            .map_err(Into::into)
            .and_then(|value| {
                if let Some(value) = value {
                    U::deserialize(&value).map(Some)
                } else {
                    Ok(None)
                }
            })
        })
        .await
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            let mut bm = RoaringBitmap::new();
            let subspace = key.subspace();
            let begin = key.serialize(0);
            key.document_id = u32::MAX;
            let end = key.serialize(0);
            let key_len = begin.len();
            for row in db.iterator_cf(
                &db.subspace_handle(subspace),
                IteratorMode::From(&begin, Direction::Forward),
            ) {
                let (key, _) = row?;
                let key = key.as_ref();
                if key.len() == key_len && key >= begin.as_slice() && key <= end.as_slice() {
                    bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                } else {
                    break;
                }
            }

            Ok(if !bm.is_empty() { Some(bm) } else { None })
        })
        .await
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let db = self.db.clone();

        self.spawn_worker(move || {
            let cf = db.subspace_handle(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let it_mode = if params.ascending {
                IteratorMode::From(&begin, Direction::Forward)
            } else {
                IteratorMode::From(&end, Direction::Reverse)
            };

            for row in db.iterator_cf(&cf, it_mode) {
                let (key, value) = row?;
                if key.as_ref() < begin.as_slice()
                    || key.as_ref() > end.as_slice()
                    || !cb(&key, &value)?
                    || params.first
                {
                    break;
                }
            }

            Ok(())
        })
        .await
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into();
        let db = self.db.clone();
        self.spawn_worker(move || {
            let cf = self.db.subspace_handle(key.subspace());
            let key = key.serialize(0);

            db.get_pinned_cf(&cf, &key)
                .map_err(Into::into)
                .and_then(|bytes| {
                    Ok(if let Some(bytes) = bytes {
                        i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
                            crate::Error::InternalError("Invalid counter value.".to_string())
                        })?)
                    } else {
                        0
                    })
                })
        })
        .await
    }
}
