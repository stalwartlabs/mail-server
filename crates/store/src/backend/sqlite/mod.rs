/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use r2d2::Pool;

use self::pool::SqliteConnectionManager;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod pool;
pub mod read;
pub mod write;

pub struct SqliteStore {
    pub(crate) conn_pool: Pool<SqliteConnectionManager>,
    pub(crate) worker_pool: rayon::ThreadPool,
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::Cause::SQLite.reason(err)
}
