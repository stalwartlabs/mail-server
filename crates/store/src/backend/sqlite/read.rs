/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;
use rusqlite::OptionalExtension;

use crate::{
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN,
};

use super::SqliteStore;

impl SqliteStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut result = conn.prepare_cached(&format!(
                "SELECT v FROM {} WHERE k = ?",
                char::from(key.subspace())
            ))?;
            let key = key.serialize(0);
            result
                .query_row([&key], |row| {
                    U::deserialize(row.get_ref(0)?.as_bytes()?)
                        .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into()))
                })
                .optional()
                .map_err(Into::into)
        })
        .await
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(0);
        key.document_id = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(0);
        let conn = self.conn_pool.get()?;
        let table = char::from(key.subspace());

        self.spawn_worker(move || {
            let mut bm = RoaringBitmap::new();
            let mut query =
                conn.prepare_cached(&format!("SELECT k FROM {table} WHERE k >= ? AND k <= ?"))?;
            let mut rows = query.query([&begin, &end])?;

            while let Some(row) = rows.next()? {
                let key = row.get_ref(0)?.as_bytes()?;
                if key.len() == key_len {
                    bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
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
        let conn = self.conn_pool.get()?;

        self.spawn_worker(move || {
            let table = char::from(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let keys = if params.values { "k, v" } else { "k" };

            let mut query = conn.prepare_cached(&match (params.first, params.ascending) {
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
            })?;
            let mut rows = query.query([&begin, &end])?;

            if params.values {
                while let Some(row) = rows.next()? {
                    let key = row.get_ref(0)?.as_bytes()?;
                    let value = row.get_ref(1)?.as_bytes()?;

                    if !cb(key, value)? {
                        break;
                    }
                }
            } else {
                while let Some(row) = rows.next()? {
                    if !cb(row.get_ref(0)?.as_bytes()?, b"")? {
                        break;
                    }
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
        let table = char::from(key.subspace());
        let key = key.serialize(0);
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            match conn
                .prepare_cached(&format!("SELECT v FROM {table} WHERE k = ?"))?
                .query_row([&key], |row| row.get::<_, i64>(0))
            {
                Ok(value) => Ok(value),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }
}
