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

use super::{into_error, RqliteStore};

impl RqliteStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            let query = rqlite_rs::query!(
                &format!("SELECT v FROM {} WHERE k = ?", char::from(key.subspace())),
                key.serialize(0)
            );
            match conn.fetch(query).await.map_err(into_error) {
                Ok(rows) => U::deserialize(rows.get_by_index_opt(0)?.as_bytes()?)
                    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err.into())),
            }
        })
        .await
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(0);
        key.document_id = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(0);
        let conn = self.conn_pool.get().map_err(into_error)?;
        let table = char::from(key.subspace());

        self.spawn_worker(move || {
            let mut bm = RoaringBitmap::new();
            let mut rows = conn
                .fetch(rqlite_rs::query!(
                    &format!("SELECT k FROM {table} WHERE k >= ? AND k <= ?"),
                    begin,
                    end
                ))
                .await
                .map_err(into_error)?;

            while let Some(row) = rows.next().map_err(into_error)? {
                let key = row
                    .get_by_index(0)
                    .map_err(into_error)?
                    .as_bytes()
                    .map_err(into_error)?;
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
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        self.spawn_worker(move || {
            let table = char::from(params.begin.subspace());
            let begin = params.begin.serialize(0);
            let end = params.end.serialize(0);
            let keys = if params.values { "k, v" } else { "k" };

            let mut query = conn
                .fetch(rqlite_rs::query!(&match (params.first, params.ascending) {
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
                        format!(
                            "SELECT {keys} FROM {table} WHERE k >= ? AND k <= ? ORDER BY k DESC"
                        )
                    }
                }))
                .await
                .map_err(into_error)?;
            let mut rows = query.query([&begin, &end]).map_err(into_error)?;

            if params.values {
                while let Some(row) = rows.next().map_err(into_error)? {
                    let key = row
                        .get_by_index(0)
                        .map_err(into_error)?
                        .as_bytes()
                        .map_err(into_error)?;
                    let value = row
                        .get_by_index(1)
                        .map_err(into_error)?
                        .as_bytes()
                        .map_err(into_error)?;

                    if !cb(key, value)? {
                        break;
                    }
                }
            } else {
                while let Some(row) = rows.next().map_err(into_error)? {
                    if !cb(
                        row.get_by_index(0)
                            .map_err(into_error)?
                            .as_bytes()
                            .map_err(into_error)?,
                        b"",
                    )? {
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
    ) -> trc::Result<i64> {
        let key = key.into();
        let table = char::from(key.subspace());
        let key = key.serialize(0);
        let conn = self.conn_pool.get().map_err(into_error)?;
        self.spawn_worker(move || {
            match conn
                .fetch(rqlite_rs::query!(&format!(
                    "SELECT v FROM {table} WHERE k = ?"
                )))
                .await
                .map_err(into_error)?
                .query_row([&key], |row| row.get::<_, i64>(0))
            {
                Ok(value) => Ok(value),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(into_error(e)),
            }
        })
        .await
    }
}
