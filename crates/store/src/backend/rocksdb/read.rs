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
    query::{self, Operator},
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, IterateParams, Key, ValueKey, U32_LEN,
};

use super::{RocksDbStore, CF_BITMAPS, CF_COUNTERS, CF_INDEXES, CF_VALUES};

const INDEX_PREFIX_LEN: usize = U32_LEN + 2;

impl RocksDbStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let db = self.db.clone();
        self.spawn_worker(move || {
            db.get_pinned_cf(&db.cf_handle(CF_VALUES).unwrap(), &key.serialize(false))
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
            db.get_pinned_cf(&db.cf_handle(CF_BITMAPS).unwrap(), &key.serialize(false))
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

    pub(crate) async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        match_value: &[u8],
        op: query::Operator,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let db = self.db.clone();
        self.spawn_worker(move || {
            let prefix =
                KeySerializer::new(std::mem::size_of::<IndexKey<&[u8]>>() + match_value.len() + 1)
                    .write(account_id)
                    .write(collection)
                    .write(field)
                    .write(match_value)
                    .finalize();
            let match_prefix = &prefix[0..INDEX_PREFIX_LEN];

            let mut bm = RoaringBitmap::new();
            let it_mode = IteratorMode::From(
                &prefix,
                match op {
                    Operator::GreaterThan | Operator::GreaterEqualThan | Operator::Equal => {
                        Direction::Forward
                    }
                    _ => Direction::Reverse,
                },
            );

            for row in db.iterator_cf(&self.db.cf_handle(CF_INDEXES).unwrap(), it_mode) {
                let (key, _) = row?;
                if !key.starts_with(match_prefix) {
                    break;
                }
                let value = key
                    .get(INDEX_PREFIX_LEN..key.len() - U32_LEN)
                    .ok_or_else(|| {
                        crate::Error::InternalError(
                            "Invalid key found in 'indexes' column family.".to_string(),
                        )
                    })?;

                match op {
                    Operator::LowerThan if value >= match_value => {
                        if value == match_value {
                            continue;
                        } else {
                            break;
                        }
                    }
                    Operator::LowerEqualThan if value > match_value => break,
                    Operator::GreaterThan if value <= match_value => {
                        if value == match_value {
                            continue;
                        } else {
                            break;
                        }
                    }
                    Operator::GreaterEqualThan if value < match_value => break,
                    Operator::Equal if value != match_value => break,
                    _ => {
                        bm.insert(key.as_ref().deserialize_be_u32(key.len() - U32_LEN)?);
                    }
                }
            }

            Ok(Some(bm))
        })
        .await
    }

    pub(crate) async fn sort_index(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        field: impl Into<u8> + Sync + Send,
        ascending: bool,
        mut cb: impl for<'x> FnMut(&'x [u8], u32) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let collection = collection.into();
        let field = field.into();
        let db = self.db.clone();

        self.spawn_worker(move || {
            let prefix = IndexKeyPrefix {
                account_id,
                collection,
                field,
            }
            .serialize(false);
            let prefix_rev;

            let it_mode = if ascending {
                IteratorMode::From(&prefix, Direction::Forward)
            } else {
                prefix_rev = IndexKeyPrefix {
                    account_id,
                    collection,
                    field: field + 1,
                }
                .serialize(false);
                IteratorMode::From(&prefix_rev, Direction::Reverse)
            };

            for row in db.iterator_cf(&self.db.cf_handle(CF_INDEXES).unwrap(), it_mode) {
                let (key, _) = row?;
                if !key.starts_with(&prefix) {
                    break;
                }
                let id_pos = key.len() - U32_LEN;

                if !cb(
                    key.get(INDEX_PREFIX_LEN..id_pos).ok_or_else(|| {
                        crate::Error::InternalError("Invalid key found in index".to_string())
                    })?,
                    key.as_ref().deserialize_be_u32(id_pos)?,
                )? {
                    return Ok(());
                }
            }

            Ok(())
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
            let begin = params.begin.serialize(false);
            let end = params.end.serialize(false);
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
        let key = key.into().serialize(false);
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

    #[cfg(feature = "test_mode")]
    pub(crate) async fn assert_is_empty(&self) {
        use super::CF_LOGS;

        let db = self.db.clone();
        self.spawn_worker(move || {
            let mut delete_keys = Vec::new();

            for cf_name in [
                super::CF_BITMAPS,
                super::CF_VALUES,
                super::CF_INDEX_VALUES,
                super::CF_COUNTERS,
                super::CF_BLOB_DATA,
                super::CF_INDEXES,
                super::CF_BLOBS,
                super::CF_LOGS,
            ] {
                let cf = db.cf_handle(cf_name).unwrap();

                for row in db.iterator_cf(&cf, IteratorMode::Start) {
                    let (key_, value_) = row.unwrap();
                    let (key, value) = (key_.as_ref(), value_.as_ref());

                    if cf_name == super::CF_BITMAPS {
                        if key[0..4] != u32::MAX.to_be_bytes() {
                            let bm = RoaringBitmap::deserialize(value).unwrap();
                            if !bm.is_empty() {
                                panic!(
                                    concat!(
                                        "Table bitmaps is not empty, account {}, ",
                                        "collection {}, family {}, field {}, key {:?}: {:?}"
                                    ),
                                    u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                    key[4],
                                    key[5],
                                    key[6],
                                    key,
                                    bm
                                );
                            }
                        }
                    } else if cf_name == super::CF_VALUES {
                        // Ignore lastId counter and ID mappings
                        if key[0..4] == u32::MAX.to_be_bytes() {
                            continue;
                        }

                        panic!("Table values is not empty: {key:?} {value:?}");
                    } else if cf_name == super::CF_COUNTERS {
                        let value = i64::from_le_bytes(value[..].try_into().unwrap());
                        if value != 0 {
                            panic!(
                                "Table counter is not empty, account {:?}, quota: {}",
                                key, value,
                            );
                        }
                    } else if cf_name == super::CF_INDEX_VALUES
                        || cf_name == super::CF_BLOB_DATA
                        || cf_name == super::CF_BLOBS
                    {
                        panic!("Subspace {cf_name:?} is not empty: {key:?} {value:?}",);
                    } else if cf_name == super::CF_INDEXES {
                        panic!(
                            concat!(
                                "Table index is not empty, account {}, collection {}, ",
                                "document {}, property {}, value {:?}: {:?}"
                            ),
                            u32::from_be_bytes(key[0..4].try_into().unwrap()),
                            key[4],
                            u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                            key[5],
                            String::from_utf8_lossy(&key[6..key.len() - 4]),
                            key
                        );
                    } else if cf_name == super::CF_LOGS {
                        delete_keys.push(key.to_vec());
                    } else {
                        panic!("Unknown column family: {}", cf_name);
                    }
                }
            }

            // Delete logs
            let cf = db.cf_handle(CF_LOGS).unwrap();
            for key in delete_keys {
                db.delete_cf(&cf, &key).unwrap();
            }

            Ok(())
        })
        .await
        .unwrap();
    }
}
