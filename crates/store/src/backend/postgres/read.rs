/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use futures::{pin_mut, TryStreamExt};
use roaring::RoaringBitmap;

use crate::{
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN,
};

use super::PostgresStore;

impl PostgresStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get().await?;
        let s = conn
            .prepare_cached(&format!(
                "SELECT v FROM {} WHERE k = $1",
                char::from(key.subspace())
            ))
            .await?;
        let key = key.serialize(0);
        conn.query_opt(&s, &[&key])
            .await
            .map_err(Into::into)
            .and_then(|r| {
                if let Some(r) = r {
                    Ok(Some(U::deserialize(r.get(0))?))
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
        let conn = self.conn_pool.get().await?;
        let table = char::from(key.subspace());

        let mut bm = RoaringBitmap::new();
        let s = conn
            .prepare_cached(&format!("SELECT k FROM {table} WHERE k >= $1 AND k <= $2"))
            .await?;
        let rows = conn.query_raw(&s, &[&begin, &end]).await?;

        pin_mut!(rows);

        while let Some(row) = rows.try_next().await? {
            let key: &[u8] = row.try_get(0)?;
            if key.len() == key_len {
                bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
            }
        }
        Ok(if !bm.is_empty() { Some(bm) } else { None })
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let conn = self.conn_pool.get().await?;
        let table = char::from(params.begin.subspace());
        let begin = params.begin.serialize(0);
        let end = params.end.serialize(0);
        let keys = if params.values { "k, v" } else { "k" };

        let s = conn
            .prepare_cached(&match (params.first, params.ascending) {
                (true, true) => {
                    format!(
                        "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC LIMIT 1"
                    )
                }
                (true, false) => {
                    format!(
                    "SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC LIMIT 1"
                )
                }
                (false, true) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k ASC")
                }
                (false, false) => {
                    format!("SELECT {keys} FROM {table} WHERE k >= $1 AND k <= $2 ORDER BY k DESC")
                }
            })
            .await?;
        let rows = conn.query_raw(&s, &[&begin, &end]).await?;

        pin_mut!(rows);

        if params.values {
            while let Some(row) = rows.try_next().await? {
                let key = row.try_get::<_, &[u8]>(0)?;
                let value = row.try_get::<_, &[u8]>(1)?;

                if !cb(key, value)? {
                    break;
                }
            }
        } else {
            while let Some(row) = rows.try_next().await? {
                if !cb(row.try_get::<_, &[u8]>(0)?, b"")? {
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

        let conn = self.conn_pool.get().await?;
        let s = conn
            .prepare_cached(&format!("SELECT v FROM {table} WHERE k = $1"))
            .await?;
        match conn.query_opt(&s, &[&key]).await {
            Ok(Some(row)) => row.try_get(0).map_err(Into::into),
            Ok(None) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}
