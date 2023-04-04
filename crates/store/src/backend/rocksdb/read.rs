use std::ops::{BitAndAssign, BitOrAssign};

use roaring::RoaringBitmap;
use rocksdb::{Direction, IteratorMode};

use crate::{
    query::Operator, write::key::DeserializeBigEndian, BitmapKey, Deserialize, Error, Serialize,
    Store, BM_DOCUMENT_IDS,
};

use super::{CF_BITMAPS, CF_INDEXES, CF_VALUES, FIELD_PREFIX_LEN};

impl Store {
    #[inline(always)]
    pub fn get_value<U>(&self, key: impl Serialize) -> crate::Result<Option<U>>
    where
        U: Deserialize,
    {
        let key = key.serialize();
        if let Some(bytes) = self
            .db
            .get_pinned_cf(&self.db.cf_handle(CF_VALUES).unwrap(), &key)
            .map_err(|err| Error::InternalError(format!("get_cf failed: {}", err)))?
        {
            Ok(Some(U::deserialize(&bytes).ok_or_else(|| {
                Error::InternalError(format!("Failed to deserialize key: {:?}", key))
            })?))
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    pub fn get_values<U>(&self, keys: Vec<impl Serialize>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize,
    {
        let cf_handle = self.db.cf_handle(CF_VALUES).unwrap();
        let mut results = Vec::with_capacity(keys.len());
        for value in self.db.multi_get_cf(
            keys.into_iter()
                .map(|key| (&cf_handle, key.serialize()))
                .collect::<Vec<_>>(),
        ) {
            results.push(
                if let Some(bytes) = value
                    .map_err(|err| Error::InternalError(format!("multi_get_cf failed: {}", err)))?
                {
                    U::deserialize(&bytes)
                        .ok_or_else(|| {
                            Error::InternalError("Failed to deserialize keys.".to_string())
                        })?
                        .into()
                } else {
                    None
                },
            );
        }

        Ok(results)
    }

    pub fn get_document_ids(
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
        })
    }

    #[inline(always)]
    pub fn get_bitmap<T: AsRef<[u8]>>(
        &self,
        key: BitmapKey<T>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let key = key.serialize();
        if let Some(bytes) = self
            .db
            .get_pinned_cf(&self.db.cf_handle(CF_BITMAPS).unwrap(), &key)
            .map_err(|err| Error::InternalError(format!("get_cf failed: {}", err)))?
        {
            let bm = RoaringBitmap::deserialize(&bytes).ok_or_else(|| {
                Error::InternalError(format!("Failed to deserialize key: {:?}", &key))
            })?;
            Ok(if !bm.is_empty() { Some(bm) } else { None })
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    fn get_bitmaps<T: Serialize>(&self, keys: Vec<T>) -> crate::Result<Vec<Option<RoaringBitmap>>> {
        let cf_handle = self.db.cf_handle(CF_BITMAPS).unwrap();
        let mut results = Vec::with_capacity(keys.len());
        for value in self.db.multi_get_cf(
            keys.into_iter()
                .map(|key| (&cf_handle, key.serialize()))
                .collect::<Vec<_>>(),
        ) {
            results.push(
                if let Some(bytes) = value
                    .map_err(|err| Error::InternalError(format!("multi_get_cf failed: {}", err)))?
                {
                    RoaringBitmap::deserialize(&bytes)
                        .ok_or_else(|| {
                            Error::InternalError("Failed to deserialize keys.".to_string())
                        })?
                        .into()
                } else {
                    None
                },
            );
        }

        Ok(results)
    }

    pub(crate) fn get_bitmaps_intersection<T: Serialize>(
        &self,
        keys: Vec<T>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut result: Option<RoaringBitmap> = None;
        for bitmap in self.get_bitmaps(keys)? {
            if let Some(bitmap) = bitmap {
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

    pub(crate) fn get_bitmaps_union<T: Serialize>(
        &self,
        keys: Vec<T>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut result: Option<RoaringBitmap> = None;
        for bitmap in (self.get_bitmaps(keys)?).into_iter().flatten() {
            if let Some(result) = &mut result {
                result.bitor_assign(&bitmap);
            } else {
                result = Some(bitmap);
            }
        }
        Ok(result)
    }

    pub(crate) fn range_to_bitmap(
        &self,
        match_key: &[u8],
        match_value: &[u8],
        op: Operator,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let mut bm = RoaringBitmap::new();
        let match_prefix = &match_key[0..FIELD_PREFIX_LEN];
        for result in self.db.iterator_cf(
            &self.db.cf_handle(CF_INDEXES).unwrap(),
            IteratorMode::From(
                match_key,
                match op {
                    Operator::GreaterThan | Operator::GreaterEqualThan | Operator::Equal => {
                        Direction::Forward
                    }
                    _ => Direction::Reverse,
                },
            ),
        ) {
            let (key, _) = result
                .map_err(|err| Error::InternalError(format!("iterator_cf failed: {}", err)))?;
            if !key.starts_with(match_prefix) {
                break;
            }
            let doc_id_pos = key.len() - std::mem::size_of::<u32>();
            let value = key.get(FIELD_PREFIX_LEN..doc_id_pos).ok_or_else(|| {
                Error::InternalError("Invalid key found in 'indexes' column family.".to_string())
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
                    bm.insert(key.as_ref().deserialize_be_u32(doc_id_pos).ok_or_else(|| {
                        Error::InternalError(
                            "Invalid key found in 'indexes' column family.".to_string(),
                        )
                    })?);
                }
            }
        }

        Ok(Some(bm))
    }
}
