/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use r2d2::Pool;
use tokio::sync::oneshot;
use utils::config::{utils::AsKey, Config};

use crate::*;

use super::{into_error, pool::SqliteConnectionManager, SqliteStore};

impl SqliteStore {
    pub fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let db = Self {
            conn_pool: Pool::builder()
                .max_size(
                    config
                        .property((&prefix, "pool.max-connections"))
                        .unwrap_or_else(|| (num_cpus::get() * 4) as u32),
                )
                .build(
                    SqliteConnectionManager::file(config.value_require((&prefix, "path"))?)
                        .with_init(|c| {
                            c.execute_batch(concat!(
                                "PRAGMA journal_mode = WAL; ",
                                "PRAGMA synchronous = NORMAL; ",
                                "PRAGMA temp_store = memory;",
                                "PRAGMA busy_timeout = 30000;"
                            ))
                        }),
                )
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!("Failed to build connection pool: {err}"),
                    )
                })
                .ok()?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(std::cmp::max(
                    config
                        .property::<usize>((&prefix, "pool.workers"))
                        .filter(|v| *v > 0)
                        .unwrap_or_else(num_cpus::get),
                    4,
                ))
                .build()
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!("Failed to build worker pool: {err}"),
                    )
                })
                .ok()?,
        };

        if let Err(err) = db.create_tables() {
            config.new_build_error(prefix.as_str(), format!("Failed to create tables: {err}"));
        }

        Some(db)
    }

    #[cfg(feature = "test_mode")]
    pub fn open_memory() -> trc::Result<Self> {
        use super::into_error;

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(1)
                .build(SqliteConnectionManager::memory())
                .map_err(into_error)?,
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|err| {
                    into_error(err).ctx(trc::Key::Reason, "Failed to build worker pool")
                })?,
        };
        db.create_tables()?;
        Ok(db)
    }

    pub(super) fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_DIRECTORY,
            SUBSPACE_FTS_QUEUE,
            SUBSPACE_BLOB_RESERVE,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_LOOKUP_VALUE,
            SUBSPACE_PROPERTY,
            SUBSPACE_SETTINGS,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_FTS_INDEX,
            SUBSPACE_LOGS,
            SUBSPACE_BLOBS,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY,
                        v BLOB NOT NULL
                    )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [
            SUBSPACE_INDEXES,
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BLOB PRIMARY KEY
                    )"
                ),
                [],
            )
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BLOB PRIMARY KEY,
                    v INTEGER NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                [],
            )
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub async fn spawn_worker<U, V>(&self, mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
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
            Err(err) => Err(trc::Cause::Thread.reason(err)),
        }
    }
}
