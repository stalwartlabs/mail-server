/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use r2d2::Pool;

use self::pool::SqliteConnectionManager;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod pool;
pub mod read;
pub mod write;

impl From<r2d2::Error> for crate::Error {
    fn from(err: r2d2::Error) -> Self {
        Self::InternalError(format!("Connection pool error: {}", err))
    }
}

impl From<rusqlite::Error> for crate::Error {
    fn from(err: rusqlite::Error) -> Self {
        Self::InternalError(format!("SQLite error: {}", err))
    }
}

impl From<rusqlite::types::FromSqlError> for crate::Error {
    fn from(err: rusqlite::types::FromSqlError) -> Self {
        Self::InternalError(format!("SQLite error: {}", err))
    }
}

pub struct SqliteStore {
    pub(crate) conn_pool: Pool<SqliteConnectionManager>,
    pub(crate) worker_pool: rayon::ThreadPool,
}
