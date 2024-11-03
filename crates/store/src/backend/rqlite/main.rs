/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use r2d2::Pool;
use tokio::sync::oneshot;
use utils::config::{utils::AsKey, Config};

use crate::*;

use super::{into_error, pool::RqliteConnectionManager, RqliteStore};

impl RqliteStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let endpoints = config
            .properties::<String>((&prefix, "endpoints"))
            .into_iter()
            .map(|(_key, addr_str)| addr_str)
            .collect::<Vec<String>>();

        let db = Self {
            conn_pool: Pool::builder()
                .max_size(
                    config
                        .property((&prefix, "pool.max-connections"))
                        .unwrap_or_else(|| (num_cpus::get() * 4) as u32),
                )
                .build(RqliteConnectionManager::endpoints(endpoints))
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

        if let Err(err) = db.create_tables().await {
            config.new_build_error(prefix.as_str(), format!("Failed to create tables: {err}"));
        }

        Some(db)
    }

    pub(crate) async fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().map_err(into_error)?;

        for table in [
            SUBSPACE_ACL,
            SUBSPACE_DIRECTORY,
            SUBSPACE_TASK_QUEUE,
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
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_TELEMETRY_INDEX,
        ] {
            let table = char::from(table);
            conn.exec(rqlite_rs::query!(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                            k TINYBLOB,
                            v MEDIUMBLOB NOT NULL,
                            PRIMARY KEY (k(255))
                        ) ENGINE=InnoDB"
            )))
            .await
            .map_err(into_error)?;
        }

        conn.exec(rqlite_rs::query!(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                        k TINYBLOB,
                        v LONGBLOB NOT NULL,
                        PRIMARY KEY (k(255))
                    ) ENGINE=InnoDB",
            char::from(SUBSPACE_BLOBS),
        )))
        .await
        .map_err(into_error)?;

        for table in [
            SUBSPACE_INDEXES,
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
        ] {
            let table = char::from(table);
            conn.exec(rqlite_rs::query!(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                            k BLOB,
                            PRIMARY KEY (k(400))
                        ) ENGINE=InnoDB"
            )))
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            conn.exec(rqlite_rs::query!(&format!(
                "CREATE TABLE IF NOT EXISTS {} (
                            k TINYBLOB,
                            v BIGINT NOT NULL DEFAULT 0,
                            PRIMARY KEY (k(255))
                        ) ENGINE=InnoDB",
                char::from(table)
            )))
            .await
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
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }
}
