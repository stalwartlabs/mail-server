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

use mysql_async::prelude::Queryable;

use super::MysqlStore;

impl MysqlStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn.prep("SELECT v FROM t WHERE k = ?").await?;
        conn.exec_first::<Vec<u8>, _, _>(&s, (key,))
            .await
            .map(|bytes| {
                if range.start == 0 && range.end == u32::MAX {
                    bytes
                } else {
                    bytes.map(|bytes| {
                        bytes
                            .get(
                                range.start as usize
                                    ..std::cmp::min(bytes.len(), range.end as usize),
                            )
                            .unwrap_or_default()
                            .to_vec()
                    })
                }
            })
            .map_err(Into::into)
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn
            .prep("INSERT INTO t (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)")
            .await?;
        conn.exec_drop(&s, (key, data))
            .await
            .map_err(|e| crate::Error::InternalError(format!("Failed to insert blob: {}", e)))
            .map(|_| ())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn.prep("DELETE FROM t WHERE k = ?").await?;
        conn.exec_iter(&s, (key,))
            .await
            .map_err(|e| crate::Error::InternalError(format!("Failed to delete blob: {}", e)))
            .map(|hits| hits.affected_rows() > 0)
    }
}
