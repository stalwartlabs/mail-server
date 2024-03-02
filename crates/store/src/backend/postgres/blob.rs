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

use std::ops::Range;

use super::PostgresStore;

impl PostgresStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let conn = self.conn_pool.get().await?;
        let s = conn.prepare_cached("SELECT v FROM t WHERE k = $1").await?;
        conn.query_opt(&s, &[&key])
            .await
            .and_then(|row| {
                if let Some(row) = row {
                    Ok(Some(if range.start == 0 && range.end == usize::MAX {
                        row.try_get::<_, Vec<u8>>(0)?
                    } else {
                        let bytes = row.try_get::<_, &[u8]>(0)?;
                        bytes
                            .get(range.start..std::cmp::min(bytes.len(), range.end))
                            .unwrap_or_default()
                            .to_vec()
                    }))
                } else {
                    Ok(None)
                }
            })
            .map_err(Into::into)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let conn = self.conn_pool.get().await?;
        let s = conn
            .prepare_cached(
                "INSERT INTO t (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
            )
            .await?;
        conn.execute(&s, &[&key, &data])
            .await
            .map_err(|e| crate::Error::InternalError(format!("Failed to insert blob: {}", e)))
            .map(|_| ())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        let conn = self.conn_pool.get().await?;
        let s = conn.prepare_cached("DELETE FROM t WHERE k = $1").await?;
        conn.execute(&s, &[&key])
            .await
            .map_err(|e| crate::Error::InternalError(format!("Failed to delete blob: {}", e)))
            .map(|hits| hits > 0)
    }
}
