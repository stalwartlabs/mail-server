/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use rusqlite::OptionalExtension;

use super::SqliteStore;

impl SqliteStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            let mut result = conn.prepare_cached("SELECT v FROM t WHERE k = ?")?;
            result
                .query_row([&key], |row| {
                    Ok({
                        let bytes = row.get_ref(0)?.as_bytes()?;
                        if range.start == 0 && range.end == usize::MAX {
                            bytes.to_vec()
                        } else {
                            bytes
                                .get(range.start..std::cmp::min(bytes.len(), range.end))
                                .unwrap_or_default()
                                .to_vec()
                        }
                    })
                })
                .optional()
                .map_err(Into::into)
        })
        .await
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            conn.prepare_cached("INSERT OR REPLACE INTO t (k, v) VALUES (?, ?)")?
                .execute([key, data])
                .map_err(|e| crate::Error::InternalError(format!("Failed to insert blob: {}", e)))
                .map(|_| ())
        })
        .await
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        let conn = self.conn_pool.get()?;
        self.spawn_worker(move || {
            conn.prepare_cached("DELETE FROM t WHERE k = ?")?
                .execute([key])
                .map_err(|e| crate::Error::InternalError(format!("Failed to delete blob: {}", e)))
                .map(|_| true)
        })
        .await
    }
}
