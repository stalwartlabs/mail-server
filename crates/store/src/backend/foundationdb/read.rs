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
    options::{self, StreamingMode},
    KeySelector, RangeOption,
};
use futures::StreamExt;
use roaring::RoaringBitmap;

use crate::{
    query::{self, Operator},
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, Key, LogKey, StoreRead, ValueKey,
    SUBSPACE_INDEXES, SUBSPACE_QUOTAS,
};

use super::{bitmap::DeserializeBlock, FdbStore};

#[async_trait::async_trait]
impl StoreRead for FdbStore {
    async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize(true);
        let trx = self.db.create_trx()?;

        if let Some(bytes) = trx.get(&key, true).await? {
            U::deserialize(&bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();
        let begin = key.serialize(true);
        key.block_num = u32::MAX;
        let end = key.serialize(true);
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
                    bm.deserialize_block(
                        value.value(),
                        key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?,
                    );
                }
            }
        }
        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        value: Vec<u8>,
        op: query::Operator,
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
        let trx = self.db.create_trx()?;
        let mut range_stream = trx.get_ranges(opt, true);

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

    async fn sort_index(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        field: impl Into<u8> + Sync + Send,
        ascending: bool,
        mut cb: impl for<'x> FnMut(&'x [u8], u32) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let collection = collection.into();
        let field = field.into();

        let from_key = IndexKeyPrefix {
            account_id,
            collection,
            field,
        }
        .serialize(true);
        let to_key = IndexKeyPrefix {
            account_id,
            collection,
            field: field + 1,
        }
        .serialize(true);
        let prefix_len = from_key.len();
        let trx = self.db.create_trx()?;
        let mut sorted_iter = trx.get_ranges(
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
                )? {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn iterate(
        &self,
        begin: impl Key,
        end: impl Key,
        first: bool,
        ascending: bool,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let begin = begin.serialize(true);
        let end = end.serialize(true);

        let trx = self.db.create_trx()?;
        let mut iter = trx.get_ranges(
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

                if !cb(key, value)? || first {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
    ) -> crate::Result<Option<u64>> {
        let collection = collection.into();
        let from_key = LogKey {
            account_id,
            collection,
            change_id: 0,
        }
        .serialize(true);
        let to_key = LogKey {
            account_id,
            collection,
            change_id: u64::MAX,
        }
        .serialize(true);

        let trx = self.db.create_trx()?;
        let mut iter = trx.get_ranges(
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

    async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(true);
        if let Some(bytes) = self.db.create_trx()?.get(&key, true).await? {
            Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
                crate::Error::InternalError("Invalid counter value.".to_string())
            })?))
        } else {
            Ok(0)
        }
    }

    #[cfg(feature = "test_mode")]
    async fn assert_is_empty(&self) {
        use crate::{StorePurge, SUBSPACE_BITMAPS, SUBSPACE_LOGS, SUBSPACE_VALUES};

        // Purge bitmaps
        self.purge_bitmaps().await.unwrap();

        let conn = self.db.create_trx().unwrap();

        let mut iter = conn.get_ranges(
            RangeOption {
                begin: KeySelector::first_greater_or_equal(&[0u8][..]),
                end: KeySelector::first_greater_or_equal(&[u8::MAX][..]),
                mode: options::StreamingMode::WantAll,
                reverse: false,
                ..Default::default()
            },
            true,
        );

        let mut delete_keys = Vec::new();
        while let Some(values) = iter.next().await {
            for value in values.unwrap() {
                let key_ = value.key();
                let value = value.value();
                let subspace = key_[0];
                let key = &key_[1..];

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
                        // Ignore lastId counter and ID mappings
                        if key[0..4] == u32::MAX.to_be_bytes() {
                            continue;
                        } else if key.len() == 4
                            && value.len() == 8
                            && u32::deserialize(key).is_ok()
                            && u64::deserialize(value).is_ok()
                        {
                            if u32::deserialize(key).unwrap() != u32::MAX {
                                delete_keys.push(key.to_vec());
                            }
                            continue;
                        }

                        panic!("Table values is not empty: {key:?} {value:?}");
                    }
                    SUBSPACE_BITMAPS => {
                        if key[0..4] != u32::MAX.to_be_bytes() {
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
                    }
                    SUBSPACE_QUOTAS => {
                        let v = i64::from_le_bytes(value[..].try_into().unwrap());
                        if v != 0 {
                            let k = u32::from_be_bytes(key[1..].try_into().unwrap());
                            panic!("Table quotas is not empty: {k:?} = {v:?} (key {key:?})");
                        }
                    }
                    SUBSPACE_LOGS => {
                        delete_keys.push(key.to_vec());
                    }

                    _ => panic!("Invalid key found in database: {key:?} for subspace {subspace}"),
                }
            }
        }

        // Empty database
        let trx = self.db.create_trx().unwrap();
        for key in delete_keys {
            trx.clear(&key);
        }
        trx.commit().await.unwrap();

        //self.destroy().await;
        crate::backend::foundationdb::write::BITMAPS.lock().clear();
    }
}
