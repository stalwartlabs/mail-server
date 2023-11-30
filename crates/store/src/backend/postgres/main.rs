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

use crate::{
    backend::postgres::tls::MakeRustlsConnect, SUBSPACE_BITMAPS, SUBSPACE_BLOBS,
    SUBSPACE_BLOB_DATA, SUBSPACE_COUNTERS, SUBSPACE_INDEXES, SUBSPACE_INDEX_VALUES, SUBSPACE_LOGS,
    SUBSPACE_VALUES,
};

use super::PostgresStore;

use deadpool_postgres::{
    Config, CreatePoolError, ManagerConfig, PoolConfig, RecyclingMethod, Runtime,
};
use tokio_postgres::NoTls;
use utils::rustls_client_config;

impl PostgresStore {
    pub async fn open(config: &utils::config::Config) -> crate::Result<Self> {
        let mut cfg = Config::new();
        cfg.dbname = config
            .value_require("store.db.database")?
            .to_string()
            .into();
        cfg.host = config.value("store.db.host").map(|s| s.to_string());
        cfg.user = config.value("store.db.user").map(|s| s.to_string());
        cfg.password = config.value("store.db.password").map(|s| s.to_string());
        cfg.port = config.property("store.db.port")?;
        cfg.connect_timeout = config.property("store.db.timeout")?;
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        if let Some(max_conn) = config.property::<usize>("store.db.pool.max-connections")? {
            cfg.pool = PoolConfig::new(max_conn).into();
        }
        let db = Self {
            conn_pool: if config.property_or_static::<bool>("store.db.tls.enable", "false")? {
                cfg.create_pool(
                    Some(Runtime::Tokio1),
                    MakeRustlsConnect::new(rustls_client_config(
                        config.property_or_static("store.db.tls.allow-invalid-certs", "false")?,
                    )),
                )?
            } else {
                cfg.create_pool(Some(Runtime::Tokio1), NoTls)?
            },
        };

        db.create_tables().await?;

        Ok(db)
    }

    pub(super) async fn create_tables(&self) -> crate::Result<()> {
        let conn = self.conn_pool.get().await?;

        for table in [
            SUBSPACE_VALUES,
            SUBSPACE_LOGS,
            SUBSPACE_INDEX_VALUES,
            SUBSPACE_BLOB_DATA,
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
            .await?;
        }

        for table in [SUBSPACE_INDEXES, SUBSPACE_BITMAPS, SUBSPACE_BLOBS] {
            let table = char::from(table);
            conn.execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {table} (
                        k BYTEA PRIMARY KEY
                    )"
                ),
                &[],
            )
            .await?;
        }

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    k BYTEA PRIMARY KEY,
                    v BIGINT NOT NULL DEFAULT 0
                )",
                char::from(SUBSPACE_COUNTERS)
            ),
            &[],
        )
        .await?;

        Ok(())
    }
}

impl From<CreatePoolError> for crate::Error {
    fn from(err: CreatePoolError) -> Self {
        crate::Error::InternalError(format!("Failed to create connection pool: {}", err))
    }
}
