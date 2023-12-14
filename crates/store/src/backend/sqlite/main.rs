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

use r2d2::Pool;
use tokio::sync::oneshot;
use utils::{
    config::{utils::AsKey, Config},
    UnwrapFailure,
};

use crate::{
    SUBSPACE_BITMAPS, SUBSPACE_BLOBS, SUBSPACE_BLOB_DATA, SUBSPACE_COUNTERS, SUBSPACE_INDEXES,
    SUBSPACE_LOGS, SUBSPACE_VALUES,
};

use super::{pool::SqliteConnectionManager, SqliteStore};

impl SqliteStore {
    pub async fn open(config: &Config, prefix: impl AsKey) -> crate::Result<Self> {
        let prefix = prefix.as_key();
        let db = Self {
            conn_pool: Pool::builder()
                .max_size(config.property_or_static((&prefix, "pool.max-connections"), "10")?)
                .build(
                    SqliteConnectionManager::file(
                        config
                            .value_require((&prefix, "path"))
                            .failed("Invalid configuration file"),
                    )
                    .with_init(|c| {
                        c.execute_batch(concat!(
                            "PRAGMA journal_mode = WAL; ",
                            "PRAGMA synchronous = NORMAL; ",
                            "PRAGMA temp_store = memory;",
                            "PRAGMA busy_timeout = 30000;"
                        ))
                    }),
                )?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(
                    config
                        .property::<usize>((&prefix, "pool.workers"))?
                        .filter(|v| *v > 0)
                        .unwrap_or_else(num_cpus::get),
                )
                .build()
                .map_err(|err| {
                    crate::Error::InternalError(format!("Failed to build worker pool: {}", err))
                })?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(super) fn create_tables(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get()?;

        for table in [SUBSPACE_VALUES, SUBSPACE_LOGS, SUBSPACE_BLOB_DATA] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )?;
        }

        for table in [SUBSPACE_INDEXES, SUBSPACE_BLOBS, SUBSPACE_BITMAPS] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY
                    )"
                ),
                [],
            )?;
        }

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY,
                    v INTEGER NOT NULL DEFAULT 0
                )",
                char::from(SUBSPACE_COUNTERS)
            ),
            [],
        )?;

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> crate::Result<V>
    where
        U: FnMut() -> crate::Result<V> + Send,
        V: Sync + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.worker_pool.scope(|s| {
            s.spawn(|_| {
                tx.send(f()).ok();
            });
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(crate::Error::InternalError(format!(
                "Worker thread failed: {}",
                err
            ))),
        }
    }
}
