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

use std::{
    ops::BitAndAssign,
    time::{Duration, Instant},
};

use foundationdb::{
    options::{self, StreamingMode},
    KeySelector, RangeOption,
};
use futures::StreamExt;
use roaring::RoaringBitmap;

use crate::{
    query::Operator,
    write::key::{DeserializeBigEndian, KeySerializer},
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, Key, LogKey, ReadTransaction, Serialize,
    Store, SUBSPACE_INDEXES,
};

use super::bitmap::DeserializeBlock;

impl ReadTransaction<'_> {
    #[inline(always)]
    pub async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize();

        if let Some(bytes) = self.trx.get(&key, true).await? {
            U::deserialize(&bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn get_bitmap_<T: AsRef<[u8]>>(
        &self,
        mut key: BitmapKey<T>,
        bm: &mut RoaringBitmap,
    ) -> crate::Result<()> {
        let begin = (&key).serialize();
        key.block_num = u32::MAX;
        let end = key.serialize();
        let key_len = begin.len();
        let mut values = self.trx.get_ranges(
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
                    bm.deserialize_block(
                        value.value(),
                        key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?,
                    );
                }
            }
        }

        Ok(())
    }

    pub async fn get_bitmap<T: AsRef<[u8]>>(
        &self,
        key: BitmapKey<T>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();
        self.get_bitmap_(key, &mut bm).await?;
        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn get_bitmaps_intersection<T: AsRef<[u8]>>(
        &self,
        keys: Vec<BitmapKey<T>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut result: Option<RoaringBitmap> = None;
        for key in keys {
            if let Some(bitmap) = self.get_bitmap(key).await? {
                if let Some(result) = &mut result {
                    result.bitand_assign(&bitmap);
                    if result.is_empty() {
                        break;
                    }
                } else {
                    result = Some(bitmap);
                }
            } else {
                return Ok(None);
            }
        }
        Ok(result)
    }

    pub(crate) async fn get_bitmaps_union<T: AsRef<[u8]>>(
        &self,
        keys: Vec<BitmapKey<T>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();

        for key in keys {
            self.get_bitmap_(key, &mut bm).await?;
        }

        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        value: Vec<u8>,
        op: Operator,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let k1 = KeySerializer::new(
            std::mem::size_of::<IndexKey<&[u8]>>() + value.len() + 1 + std::mem::size_of::<u32>(),
        )
        .write(SUBSPACE_INDEXES)
        .write(account_id)
        .write(collection)
        .write(field);
        let k2 = KeySerializer::new(
            std::mem::size_of::<IndexKey<&[u8]>>() + value.len() + 1 + std::mem::size_of::<u32>(),
        )
        .write(SUBSPACE_INDEXES)
        .write(account_id)
        .write(collection)
        .write(field + matches!(op, Operator::GreaterThan | Operator::GreaterEqualThan) as u8);

        let (begin, end) = match op {
            Operator::LowerThan => (
                KeySelector::first_greater_or_equal(k1.finalize()),
                KeySelector::first_greater_or_equal(k2.write(&value[..]).write(0u32).finalize()),
            ),
            Operator::LowerEqualThan => (
                KeySelector::first_greater_or_equal(k1.finalize()),
                KeySelector::first_greater_or_equal(
                    k2.write(&value[..]).write(u32::MAX).finalize(),
                ),
            ),
            Operator::GreaterThan => (
                KeySelector::first_greater_than(k1.write(&value[..]).write(u32::MAX).finalize()),
                KeySelector::first_greater_or_equal(k2.finalize()),
            ),
            Operator::GreaterEqualThan => (
                KeySelector::first_greater_or_equal(k1.write(&value[..]).write(0u32).finalize()),
                KeySelector::first_greater_or_equal(k2.finalize()),
            ),
            Operator::Equal => (
                KeySelector::first_greater_or_equal(k1.write(&value[..]).write(0u32).finalize()),
                KeySelector::first_greater_or_equal(
                    k2.write(&value[..]).write(u32::MAX).finalize(),
                ),
            ),
        };
        let key_len = begin.key().len();

        let opt = RangeOption {
            begin,
            end,
            mode: StreamingMode::WantAll,
            reverse: false,
            ..RangeOption::default()
        };

        let mut bm = RoaringBitmap::new();
        let mut range_stream = self.trx.get_ranges(opt, true);

        if op != Operator::Equal {
            while let Some(values) = range_stream.next().await {
                for value in values? {
                    let key = value.key();
                    bm.insert(key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?);
                }
            }
        } else {
            while let Some(values) = range_stream.next().await {
                for value in values? {
                    let key = value.key();
                    if key.len() == key_len {
                        bm.insert(key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?);
                    }
                }
            }
        }

        Ok(Some(bm))
    }

    pub(crate) async fn sort_index(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        ascending: bool,
        mut cb: impl FnMut(&[u8], u32) -> bool,
    ) -> crate::Result<()> {
        let from_key = IndexKeyPrefix {
            account_id,
            collection,
            field,
        }
        .serialize();
        let to_key = IndexKeyPrefix {
            account_id,
            collection,
            field: field + 1,
        }
        .serialize();
        let prefix_len = from_key.len();
        let mut sorted_iter = self.trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&from_key),
                end: KeySelector::first_greater_or_equal(&to_key),
                mode: options::StreamingMode::Iterator,
                reverse: !ascending,
                ..Default::default()
            },
            true,
        );

        while let Some(values) = sorted_iter.next().await {
            for value in values? {
                let key = value.key();
                let id_pos = key.len() - std::mem::size_of::<u32>();
                debug_assert!(key.starts_with(&from_key));
                if !cb(
                    key.get(prefix_len..id_pos).ok_or_else(|| {
                        crate::Error::InternalError("Invalid key found in index".to_string())
                    })?,
                    key.deserialize_be_u32(id_pos)?,
                ) {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn iterate<T>(
        &self,
        mut acc: T,
        begin: impl Key,
        end: impl Key,
        first: bool,
        ascending: bool,
        cb: impl Fn(&mut T, &[u8], &[u8]) -> crate::Result<bool> + Sync + Send + 'static,
    ) -> crate::Result<T> {
        let begin = begin.serialize();
        let end = end.serialize();

        let mut iter = self.trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&begin),
                end: KeySelector::first_greater_than(&end),
                mode: if first {
                    options::StreamingMode::Small
                } else {
                    options::StreamingMode::Iterator
                },
                reverse: !ascending,
                ..Default::default()
            },
            true,
        );

        while let Some(values) = iter.next().await {
            for value in values? {
                let key = value.key().get(1..).unwrap_or_default();
                let value = value.value();

                if !cb(&mut acc, key, value)? || first {
                    return Ok(acc);
                }
            }
        }

        Ok(acc)
    }

    pub(crate) async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: u8,
    ) -> crate::Result<Option<u64>> {
        let from_key = LogKey {
            account_id,
            collection,
            change_id: 0,
        }
        .serialize();
        let to_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        }
        .serialize();

        let mut iter = self.trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&from_key),
                end: KeySelector::first_greater_or_equal(&to_key),
                mode: options::StreamingMode::Small,
                reverse: true,
                ..Default::default()
            },
            true,
        );

        while let Some(values) = iter.next().await {
            if let Some(value) = (values?).into_iter().next() {
                let key = value.key();

                return key
                    .deserialize_be_u64(key.len() - std::mem::size_of::<u64>())
                    .map(Some);
            }
        }

        Ok(None)
    }

    pub async fn refresh_if_old(&mut self) -> crate::Result<()> {
        if self.trx_age.elapsed() > Duration::from_millis(2000) {
            self.trx = self.db.create_trx()?;
            self.trx_age = Instant::now();
        }
        Ok(())
    }
}

impl Store {
    pub async fn read_transaction(&self) -> crate::Result<ReadTransaction<'_>> {
        Ok(ReadTransaction {
            db: &self.db,
            trx: self.db.create_trx()?,
            trx_age: Instant::now(),
        })
    }

    #[cfg(feature = "test_mode")]
    pub async fn assert_is_empty(&self) {
        use crate::{SUBSPACE_BITMAPS, SUBSPACE_LOGS, SUBSPACE_VALUES};

        // Purge bitmaps
        self.purge_bitmaps().await.unwrap();

        let conn = self.read_transaction().await.unwrap();

        let mut iter = conn.trx.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&[0u8][..]),
                end: KeySelector::first_greater_or_equal(&[u8::MAX][..]),
                mode: options::StreamingMode::WantAll,
                reverse: false,
                ..Default::default()
            },
            true,
        );

        while let Some(values) = iter.next().await {
            for value in values.unwrap() {
                let key = value.key();
                let value = value.value();
                let subspace = key[0];
                let key = &key[1..];

                match subspace {
                    SUBSPACE_INDEXES => {
                        panic!(
                            "Table index is not empty, account {}, collection {}, document {}, property {}, value {:?}: {:?}",
                            u32::from_be_bytes(key[0..4].try_into().unwrap()),
                            key[4],
                            u32::from_be_bytes(key[key.len()-4..].try_into().unwrap()),
                            key[5],
                            String::from_utf8_lossy(&key[6..key.len()-4]),
                            key
                        );
                    }
                    SUBSPACE_VALUES => {
                        // Ignore lastId counter
                        if key.len() == 4
                            && value.len() == 8
                            && u32::deserialize(key).is_ok()
                            && u64::deserialize(value).is_ok()
                        {
                            continue;
                        }

                        panic!("Table values is not empty: {key:?} {value:?}");
                    }
                    SUBSPACE_BITMAPS => {
                        panic!(
                            "Table bitmaps is not empty, account {}, collection {}, family {}, field {}, key {:?}: {:?}",
                            u32::from_be_bytes(key[0..4].try_into().unwrap()),
                            key[4],
                            key[5],
                            key[6],
                            key,
                            value
                        );
                    }
                    SUBSPACE_LOGS => (),

                    _ => panic!("Invalid key found in database: {key:?} for subspace {subspace}"),
                }
            }
        }

        // Empty database
        self.destroy().await;
        crate::backend::foundationdb::write::BITMAPS.lock().clear();
    }
}
