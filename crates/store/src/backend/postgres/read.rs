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

use futures::{pin_mut, TryStreamExt};
use roaring::RoaringBitmap;

use crate::{
    query::{self, Operator},
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IndexKey, IndexKeyPrefix, IterateParams, Key, ValueKey, U32_LEN,
};

use super::PostgresStore;

impl PostgresStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let key = key.serialize(false);
        let conn = self.conn_pool.get().await?;
        let s = conn.prepare_cached("SELECT v FROM v WHERE k = $1").await?;
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
        mut key: BitmapKey<BitmapClass>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let begin = key.serialize(false);
        key.block_num = u32::MAX;
        let key_len = begin.len();
        let end = key.serialize(false);
        let conn = self.conn_pool.get().await?;

        let mut bm = RoaringBitmap::new();
        let s = conn
            .prepare_cached("SELECT k FROM b WHERE k >= $1 AND k <= $2")
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

    pub(crate) async fn range_to_bitmap(
        &self,
        account_id: u32,
        collection: u8,
        field: u8,
        value: &[u8],
        op: query::Operator,
    ) -> crate::Result<Option<RoaringBitmap>> {
        let conn = self.conn_pool.get().await?;
        let k1 =
            KeySerializer::new(std::mem::size_of::<IndexKey<&[u8]>>() + value.len() + 1 + U32_LEN)
                .write(account_id)
                .write(collection)
                .write(field);
        let k2 =
            KeySerializer::new(std::mem::size_of::<IndexKey<&[u8]>>() + value.len() + 1 + U32_LEN)
                .write(account_id)
                .write(collection)
                .write(
                    field + matches!(op, Operator::GreaterThan | Operator::GreaterEqualThan) as u8,
                );

        let (query, begin, end) = match op {
            Operator::LowerThan => (
                ("SELECT k FROM i WHERE k >= $1 AND k < $2"),
                (k1.finalize()),
                (k2.write(value).write(0u32).finalize()),
            ),
            Operator::LowerEqualThan => (
                ("SELECT k FROM i WHERE k >= $1 AND k <= $2"),
                (k1.finalize()),
                (k2.write(value).write(u32::MAX).finalize()),
            ),
            Operator::GreaterThan => (
                ("SELECT k FROM i WHERE k > $1 AND k <= $2"),
                (k1.write(value).write(u32::MAX).finalize()),
                (k2.finalize()),
            ),
            Operator::GreaterEqualThan => (
                ("SELECT k FROM i WHERE k >= $1 AND k <= $2"),
                (k1.write(value).write(0u32).finalize()),
                (k2.finalize()),
            ),
            Operator::Equal => (
                ("SELECT k FROM i WHERE k >= $1 AND k <= $2"),
                (k1.write(value).write(0u32).finalize()),
                (k2.write(value).write(u32::MAX).finalize()),
            ),
        };

        let mut bm = RoaringBitmap::new();
        let s = conn.prepare_cached(query).await?;
        let rows = conn.query_raw(&s, &[&begin, &end]).await?;

        pin_mut!(rows);

        if op != Operator::Equal {
            while let Some(row) = rows.try_next().await? {
                let key = row.try_get::<_, &[u8]>(0)?;
                bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
            }
        } else {
            let key_len = begin.len();
            while let Some(row) = rows.try_next().await? {
                let key = row.try_get::<_, &[u8]>(0)?;
                if key.len() == key_len {
                    bm.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                }
            }
        }

        Ok(Some(bm))
    }

    pub(crate) async fn sort_index(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Sync + Send,
        field: impl Into<u8> + Sync + Send,
        ascending: bool,
        mut cb: impl for<'x> FnMut(&'x [u8], u32) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let collection = collection.into();
        let field = field.into();

        let conn = self.conn_pool.get().await?;
        let begin = IndexKeyPrefix {
            account_id,
            collection,
            field,
        }
        .serialize(false);
        let end = IndexKeyPrefix {
            account_id,
            collection,
            field: field + 1,
        }
        .serialize(false);
        let prefix_len = begin.len();
        let s = conn
            .prepare_cached(if ascending {
                "SELECT k FROM i WHERE k >= $1 AND k < $2 ORDER BY k ASC"
            } else {
                "SELECT k FROM i WHERE k >= $1 AND k < $2 ORDER BY k DESC"
            })
            .await?;
        let rows = conn.query_raw(&s, &[&begin, &end]).await?;

        pin_mut!(rows);

        while let Some(row) = rows.try_next().await? {
            let key = row.try_get::<_, &[u8]>(0)?;
            let id_pos = key.len() - U32_LEN;
            debug_assert!(key.starts_with(&begin));
            if !cb(
                key.get(prefix_len..id_pos).ok_or_else(|| {
                    crate::Error::InternalError("Invalid key found in index".to_string())
                })?,
                key.deserialize_be_u32(id_pos)?,
            )? {
                return Ok(());
            }
        }

        Ok(())
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> crate::Result<bool> + Sync + Send,
    ) -> crate::Result<()> {
        let conn = self.conn_pool.get().await?;
        let table = char::from(params.begin.subspace());
        let begin = params.begin.serialize(false);
        let end = params.end.serialize(false);
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
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> crate::Result<i64> {
        let key = key.into().serialize(false);
        let conn = self.conn_pool.get().await?;
        let s = conn.prepare_cached("SELECT v FROM c WHERE k = $1").await?;
        match conn.query_opt(&s, &[&key]).await {
            Ok(Some(row)) => row.try_get(0).map_err(Into::into),
            Ok(None) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(feature = "test_mode")]
    pub(crate) async fn assert_is_empty(&self) {
        let conn = self.conn_pool.get().await.unwrap();

        // Values
        let mut has_errors = false;
        for table in [
            crate::SUBSPACE_VALUES,
            crate::SUBSPACE_INDEX_VALUES,
            crate::SUBSPACE_COUNTERS,
            crate::SUBSPACE_BLOB_DATA,
        ] {
            let table = char::from(table);
            let s = conn
                .prepare_cached(&format!("SELECT k, v FROM {table}"))
                .await
                .unwrap();
            let rows = conn.query_raw(&s, Vec::<&[u8]>::new()).await.unwrap();

            pin_mut!(rows);

            while let Some(row) = rows.try_next().await.unwrap() {
                let key = row.get::<_, &[u8]>(0);
                if table != 'c' {
                    let value = row.get::<_, &[u8]>(1);

                    if key[0..4] != u32::MAX.to_be_bytes() {
                        eprintln!("Table {table:?} is not empty: {key:?} {value:?}");
                        has_errors = true;
                    }
                } else {
                    let value = row.get::<_, i64>(1);
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
        for table in [crate::SUBSPACE_INDEXES, crate::SUBSPACE_BLOBS] {
            let table = char::from(table);
            let s = conn
                .prepare_cached(&format!("SELECT k FROM {table}"))
                .await
                .unwrap();
            let rows = conn.query_raw(&s, Vec::<&[u8]>::new()).await.unwrap();
            pin_mut!(rows);
            while let Some(row) = rows.try_next().await.unwrap() {
                let key = row.get::<_, &[u8]>(0);

                if table == 'i' {
                    eprintln!(
                        "Table index is not empty, account {}, collection {}, document {}, property {}, value {:?}: {:?}",
                        u32::from_be_bytes(key[0..4].try_into().unwrap()),
                        key[4],
                        u32::from_be_bytes(key[key.len()-4..].try_into().unwrap()),
                        key[5],
                        String::from_utf8_lossy(&key[6..key.len()-4]),
                        key
                    );
                } else {
                    eprintln!("Table {table:?} is not empty: {key:?}");
                }
                has_errors = true;
            }
        }

        // Bitmaps
        let s = conn
            .prepare_cached(&format!(
                "SELECT k FROM {}",
                char::from(crate::SUBSPACE_BITMAPS)
            ))
            .await
            .unwrap();
        let rows = conn.query_raw(&s, Vec::<&[u8]>::new()).await.unwrap();
        pin_mut!(rows);
        while let Some(row) = rows.try_next().await.unwrap() {
            let key = row.get::<_, &[u8]>(0);
            if key[0..4] != u32::MAX.to_be_bytes() {
                eprintln!("Table bitmaps failed to purge, found key: {key:?}");
                has_errors = true;
            }
        }

        // Delete logs
        conn.execute("DELETE FROM l", &[]).await.unwrap();

        if has_errors {
            panic!("Database is not empty");
        }
    }
}
