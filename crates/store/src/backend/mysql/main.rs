/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use mysql_async::{prelude::Queryable, OptsBuilder, Pool, PoolConstraints, PoolOpts, SslOpts};
use utils::config::{utils::AsKey, Config};

use crate::*;

use super::{into_error, MysqlStore};

impl MysqlStore {
    pub async fn open(
        config: &mut Config,
        prefix: impl AsKey,
        create_tables: bool,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut opts = OptsBuilder::default()
            .ip_or_hostname(config.value_require((&prefix, "host"))?.to_string())
            .user(config.value((&prefix, "user")).map(|s| s.to_string()))
            .pass(config.value((&prefix, "password")).map(|s| s.to_string()))
            .db_name(
                config
                    .value_require((&prefix, "database"))?
                    .to_string()
                    .into(),
            )
            .max_allowed_packet(config.property((&prefix, "max-allowed-packet")))
            .wait_timeout(
                config
                    .property::<Option<Duration>>((&prefix, "timeout"))
                    .unwrap_or_default()
                    .map(|t| t.as_secs() as usize),
            );
        if let Some(port) = config.property((&prefix, "port")) {
            opts = opts.tcp_port(port);
        }

        if config
            .property_or_default::<bool>((&prefix, "tls.enable"), "false")
            .unwrap_or_default()
        {
            let allow_invalid = config
                .property_or_default::<bool>((&prefix, "tls.allow-invalid-certs"), "false")
                .unwrap_or_default();
            opts = opts.ssl_opts(Some(
                SslOpts::default()
                    .with_danger_accept_invalid_certs(allow_invalid)
                    .with_danger_skip_domain_validation(allow_invalid),
            ));
        }

        // Configure connection pool
        let mut pool_min = PoolConstraints::default().min();
        let mut pool_max = PoolConstraints::default().max();
        if let Some(n_size) = config
            .property::<usize>((&prefix, "pool.min-connections"))
            .filter(|&n| n > 0)
        {
            pool_min = n_size;
        }
        if let Some(n_size) = config
            .property::<usize>((&prefix, "pool.max-connections"))
            .filter(|&n| n > 0)
        {
            pool_max = n_size;
        }
        opts = opts.pool_opts(
            PoolOpts::default().with_constraints(PoolConstraints::new(pool_min, pool_max).unwrap()),
        );

        let db = Self {
            conn_pool: Pool::new(opts),
        };

        if create_tables {
            if let Err(err) = db.create_tables().await {
                config.new_build_error(prefix.as_str(), format!("Failed to create tables: {err}"));
            }
        }

        Some(db)
    }

    pub(crate) async fn create_tables(&self) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;

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
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_TELEMETRY_INDEX,
        ] {
            let table = char::from(table);
            conn.query_drop(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k TINYBLOB,
                    v MEDIUMBLOB NOT NULL,
                    PRIMARY KEY (k(255))
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        conn.query_drop(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                k TINYBLOB,
                v LONGBLOB NOT NULL,
                PRIMARY KEY (k(255))
            ) ENGINE=InnoDB",
            char::from(SUBSPACE_BLOBS),
        ))
        .await
        .map_err(into_error)?;

        for table in [
            SUBSPACE_INDEXES,
            SUBSPACE_BITMAP_ID,
            SUBSPACE_BITMAP_TAG,
            SUBSPACE_BITMAP_TEXT,
        ] {
            let table = char::from(table);
            conn.query_drop(&format!(
                "CREATE TABLE IF NOT EXISTS {table} (
                    k BLOB,
                    PRIMARY KEY (k(400))
                ) ENGINE=InnoDB"
            ))
            .await
            .map_err(into_error)?;
        }

        for table in [SUBSPACE_COUNTER, SUBSPACE_QUOTA] {
            conn.query_drop(&format!(
                "CREATE TABLE IF NOT EXISTS {} (
                k TINYBLOB,
                v BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (k(255))
            ) ENGINE=InnoDB",
                char::from(table)
            ))
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }
}
