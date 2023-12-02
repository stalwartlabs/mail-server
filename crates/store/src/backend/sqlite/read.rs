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
            let key = key.serialize(false);
            let mut result = conn.prepare_cached("SELECT v FROM v WHERE k = ?")?;
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
        mut key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(false);
        key.block_num = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(false);
        let conn = self.conn_pool.get()?;

        self.spawn_worker(move || {
            let mut bm = RoaringBitmap::new();
            let mut query = conn.prepare_cached("SELECT k FROM b WHERE k >= ? AND k <= ?")?;
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
            let begin = params.begin.serialize(false);
            let end = params.end.serialize(false);
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
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(false);
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            match conn
                .prepare_cached("SELECT v FROM c WHERE k = ?")?
                .query_row([&key], |row| row.get::<_, i64>(0))
            {
                Ok(value) => Ok(value),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    #[cfg(feature = "test_mode")]
    pub(crate) async fn assert_is_empty(&self) {
        let conn = self.conn_pool.get().unwrap();
        self.spawn_worker(move || {
            // Values
            let mut has_errors = false;
            for table in [
                crate::SUBSPACE_VALUES,
                crate::SUBSPACE_INDEX_VALUES,
                crate::SUBSPACE_COUNTERS,
                crate::SUBSPACE_BLOB_DATA,
            ] {
                let table = char::from(table);
                let mut query = conn
                    .prepare_cached(&format!("SELECT k, v FROM {table}"))
                    .unwrap();
                let mut rows = query.query([]).unwrap();

                while let Some(row) = rows.next().unwrap() {
                    let key = row.get_ref(0).unwrap().as_bytes().unwrap();
                    if table != 'c' {
                        let value = row.get_ref(1).unwrap().as_bytes().unwrap();

                        if key[0..4] != u32::MAX.to_be_bytes() {
                            eprintln!("Table {table:?} is not empty: {key:?} {value:?}");
                            has_errors = true;
                        }
                    } else {
                        let value = row.get::<_, i64>(1).unwrap();
                        if value != 0 {
                            eprintln!(
                                "Table counter is not empty, account {:?}, quota: {}",
                                key, value,
                            );
                            has_errors = true;
                        }
                    }
                }
            }

            // Indexes
            for table in [
                crate::SUBSPACE_INDEXES,
                crate::SUBSPACE_BLOBS,
                crate::SUBSPACE_BITMAPS,
            ] {
                let table = char::from(table);
                let mut query = conn
                    .prepare_cached(&format!("SELECT k FROM {table}"))
                    .unwrap();
                let mut rows = query.query([]).unwrap();

                while let Some(row) = rows.next().unwrap() {
                    let key = row.get_ref(0).unwrap().as_bytes().unwrap();

                    if table == 'i' {
                        eprintln!(
                            concat!(
                                "Table index is not empty, account {}, ",
                                "collection {}, document {}, property {}, value {:?}: {:?}"
                            ),
                            u32::from_be_bytes(key[0..4].try_into().unwrap()),
                            key[4],
                            u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                            key[5],
                            String::from_utf8_lossy(&key[6..key.len() - 4]),
                            key
                        );
                        has_errors = true;
                    } else if table != 'b' || key[0..4] != u32::MAX.to_be_bytes() {
                        eprintln!("Table {table:?} is not empty: {key:?}");
                        has_errors = true;
                    }
                }
            }

            // Delete logs
            conn.execute("DELETE FROM l", []).unwrap();

            if has_errors {
                panic!("Database is not empty");
            }

            Ok(())
        })
        .await
        .unwrap();
    }
}
