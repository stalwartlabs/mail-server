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
        mut key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(0);
        key.block_num = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(0);
        let mut conn = self.conn_pool.get_conn().await?;

        let mut bm = RoaringBitmap::new();
        let s = conn.prep("SELECT k FROM b WHERE k >= ? AND k <= ?").await?;
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
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(0);
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn.prep("SELECT v FROM c WHERE k = ?").await?;
        match conn.exec_first::<i64, _, _>(&s, (key,)).await {
            Ok(Some(num)) => Ok(num),
            Ok(None) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}
