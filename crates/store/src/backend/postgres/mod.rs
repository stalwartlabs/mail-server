/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use deadpool_postgres::Pool;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod tls;
pub mod write;

pub struct PostgresStore {
    pub(crate) conn_pool: Pool,
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::Cause::PostgreSQL.reason(err)
}
