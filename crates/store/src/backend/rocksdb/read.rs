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

use roaring::RoaringBitmap;
use rocksdb::{Direction, IteratorMode};

use crate::{
    write::{BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, WITHOUT_BLOCK_NUM,
};

use super::{RocksDbStore, CF_BITMAPS, CF_COUNTERS};

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
        key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(
                &db.cf_handle(CF_BITMAPS).unwrap(),
                &key.serialize(WITHOUT_BLOCK_NUM),
            )
            .map_err(Into::into)
            .and_then(|value| {
                if let Some(value) = value {
                    RoaringBitmap::deserialize(&value).map(|rb| {
                        if !rb.is_empty() {
                            Some(rb)
                        } else {
                            None
                        }
                    })
                } else {
                    Ok(None)
                }
            })
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
            let cf = db
                .cf_handle(std::str::from_utf8(&[params.begin.subspace()]).unwrap())
                .unwrap();
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
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(0);
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(&db.cf_handle(CF_COUNTERS).unwrap(), &key)
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
