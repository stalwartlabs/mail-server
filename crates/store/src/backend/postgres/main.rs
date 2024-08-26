/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::{backend::postgres::tls::MakeRustlsConnect, *};

use super::{into_error, PostgresStore};

use deadpool_postgres::{Config, ManagerConfig, PoolConfig, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;
use utils::{config::utils::AsKey, rustls_client_config};

impl PostgresStore {
    pub async fn open(
        config: &mut utils::config::Config,
        prefix: impl AsKey,
        create_tables: bool,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut cfg = Config::new();
        cfg.dbname = config
            .value_require((&prefix, "database"))?
            .to_string()
            .into();
        cfg.host = config.value((&prefix, "host")).map(|s| s.to_string());
        cfg.user = config.value((&prefix, "user")).map(|s| s.to_string());
        cfg.password = config.value((&prefix, "password")).map(|s| s.to_string());
        cfg.port = config.property((&prefix, "port"));
        cfg.connect_timeout = config
            .property::<Option<Duration>>((&prefix, "timeout"))
            .unwrap_or_default();
        cfg.options = config.value((&prefix, "options")).map(|s| s.to_string());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        if let Some(max_conn) = config.property::<usize>((&prefix, "pool.max-connections")) {
            cfg.pool = PoolConfig::new(max_conn).into();
        }
        let db = Self {
            conn_pool: if config
                .property_or_default::<bool>((&prefix, "tls.enable"), "false")
                .unwrap_or_default()
            {
                cfg.create_pool(
                    Some(Runtime::Tokio1),
                    MakeRustlsConnect::new(rustls_client_config(
                        config
                            .property_or_default((&prefix, "tls.allow-invalid-certs"), "false")
                            .unwrap_or_default(),
                    )),
                )
            } else {
                cfg.create_pool(Some(Runtime::Tokio1), NoTls)
            }
            .map_err(|e| {
                config.new_build_error(
                    prefix.as_str(),
                    format!("Failed to create connection pool: {e}"),
                )
            })
            .ok()?,
        };

        if create_tables {
            if let Err(err) = db.create_tables().await {
                config.new_build_error(prefix.as_str(), format!("Failed to create tables: {err}"));
            }
        }

        Some(db)
    }

    pub(crate) async fn create_tables(&self) -> trc::Result<()> {
        let conn = self.conn_pool.get().await.map_err(into_error)?;

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
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_TELEMETRY_INDEX,
        ] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BYTEA PRIMARY KEY,
                        v BYTEA NOT NULL
                    )"
                ),
                &[],
            )
            .await
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
                        k BYTEA PRIMARY KEY
                    )"
                ),
                &[],
            )
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                    k BYTEA PRIMARY KEY,
                    v BIGINT NOT NULL DEFAULT 0
                )",
                    char::from(table)
                ),
                &[],
            )
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }
}
