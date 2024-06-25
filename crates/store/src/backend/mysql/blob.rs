/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use mysql_async::prelude::Queryable;

use super::MysqlStore;

impl MysqlStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let mut conn = self.conn_pool.get_conn().await?;
        let s = conn.prep("SELECT v FROM t WHERE k = ?").await?;
        conn.exec_first::<Vec<u8>, _, _>(&s, (key,))
            .await
            .map(|bytes| {
                if range.start == 0 && range.end == usize::MAX {
                    bytes
                } else {
                    bytes.map(|bytes| {
                        bytes
                            .get(range.start..std::cmp::min(bytes.len(), range.end))
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
