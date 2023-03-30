use std::{
    ops::{BitAndAssign, BitOrAssign},
    time::{Duration, Instant},
};

use foundationdb::{
    options::{self, StreamingMode},
    Database, KeySelector, RangeOption, Transaction,
};
use futures::StreamExt;
use roaring::RoaringBitmap;

use crate::{
    query::Operator,
    write::key::{DeserializeBigEndian, KeySerializer},
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, Serialize, Store, ValueKey, BM_DOCUMENT_IDS,
};

use super::{bitmap::DeserializeBlock, SUBSPACE_INDEXES};

pub struct ReadTransaction<'x> {
    db: &'x Database,
    pub trx: Transaction,
    trx_age: Instant,
}

impl ReadTransaction<'_> {
    #[inline(always)]
    pub async fn get_value<U>(&self, key: ValueKey) -> crate::Result<Option<U>>
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

    #[inline(always)]
    pub async fn get_values<U>(&self, keys: Vec<ValueKey>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize,
    {
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            results.push(self.get_value(key).await?);
        }

        Ok(results)
    }

    pub async fn get_document_ids(
        &self,
        account_id: u32,
        collection: u8,
    ) -> crate::Result<Option<RoaringBitmap>> {
        self.get_bitmap(BitmapKey {
            account_id,
            collection,
            family: BM_DOCUMENT_IDS,
            field: u8::MAX,
            key: b"",
            block_num: 0,
        })
        .await
    }

    async fn get_bitmap_<T: AsRef<[u8]>>(
        &self,
        mut key: BitmapKey<T>,
        bm: &mut RoaringBitmap,
    ) -> crate::Result<()> {
        let from_key = key.serialize();
        key.block_num = u32::MAX;
        let to_key = key.serialize();
        let opt = RangeOption {
            mode: StreamingMode::WantAll,
            reverse: false,
            ..RangeOption::from((from_key.as_ref(), to_key.as_ref()))
        };
        let mut values = self.trx.get_ranges(opt, true);

        while let Some(values) = values.next().await {
            for value in values? {
                let key = value.key();
                bm.deserialize_block(
                    value.value(),
                    value
                        .key()
                        .deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?,
                );
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

        let opt = RangeOption {
            begin,
            end,
            mode: StreamingMode::WantAll,
            reverse: false,
            ..RangeOption::default()
        };

        let mut bm = RoaringBitmap::new();
        let mut range_stream = self.trx.get_ranges(opt, true);

        while let Some(values) = range_stream.next().await {
            for value in values? {
                let key = value.key();
                bm.insert(key.deserialize_be_u32(key.len() - std::mem::size_of::<u32>())?);
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
}
