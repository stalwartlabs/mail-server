/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use futures::TryStreamExt;
use mysql_async::{prelude::Queryable, Row};
use roaring::RoaringBitmap;

use crate::{
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN,
};

use super::MysqlStore;

impl MysqlStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn
            .prep(&format!(
                "SELECT v FROM {} WHERE k = ?",
                char::from(key.subspace())
            ))
            .await?;
        let key = key.serialize(0);
        conn.exec_first::<Vec<u8>, _, _>(&s, (key,))
            .await
            .map_err(Into::into)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize(&r)?))
                } else {
                    Ok(None)
                }
            })
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(0);
        key.document_id = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(0);
        let mut conn = self.conn_pool.get_conn().await?;
        let table = char::from(key.subspace());

        let mut bm = RoaringBitmap::new();
        let s = conn
            .prep(&format!("SELECT k FROM {table} WHERE k >= ? AND k <= ?"))
            .await?;
        let mut rows = conn.exec_stream::<Vec<u8>, _, _>(&s, (begin, end)).await?;

        while let Some(key) = rows.try_next().await? {
            if key.len() == key_len {
                bm.insert(key.as_slice().deserialize_be_u32(key.len() - U32_LEN)?);
            }
        }
        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let mut conn = self.conn_pool.get_conn().await?;
        let table = char::from(params.begin.subspace());
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let keys = if params.values { "k, v" } else { "k" };

        let s = conn
            .prep(&match (params.first, params.ascending) {
                (true, true) => {
                    format!(
                        "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC LIMIT 1"
                    )
                }
                (true, false) => {
                    format!(
                    "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC LIMIT 1"
                )
                }
                (false, true) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k ASC")
                }
                (false, false) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC")
                }
            })
            .await?;
        let mut rows = conn.exec_stream::<Row, _, _>(&s, (begin, end)).await?;

        if params.values {
            while let Some(mut row) = rows.try_next().await? {
                let value = row
                    .take_opt::<Vec<u8>, _>(1)
                    .unwrap_or_else(|| Ok(vec![]))?;
                let key = row
                    .take_opt::<Vec<u8>, _>(0)
                    .unwrap_or_else(|| Ok(vec![]))?;

                if !cb(&key, &value)? {
                    break;
                }
            }
        } else {
            while let Some(mut row) = rows.try_next().await? {
                if !cb(
                    &row.take_opt::<Vec<u8>, _>(0)
                        .unwrap_or_else(|| Ok(vec![]))?,
                    b"",
                )? {
                    break;
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into();
        let table = char::from(key.subspace());
        let key = key.serialize(0);
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn
            .prep(&format!("SELECT v FROM {table} WHERE k = ?"))
            .await?;
        match conn.exec_first::<i64, _, _>(&s, (key,)).await {
            Ok(Some(num)) => Ok(num),
            Ok(None) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}
