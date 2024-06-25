/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mysql_async::Pool;

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod write;

pub struct MysqlStore {
    pub(crate) conn_pool: Pool,
}

impl From<mysql_async::Error> for crate::Error {
    fn from(err: mysql_async::Error) -> Self {
        Self::InternalError(format!("mySQL error: {}", err))
    }
}

impl From<mysql_async::FromValueError> for crate::Error {
    fn from(err: mysql_async::FromValueError) -> Self {
        Self::InternalError(format!("mySQL value conversion error: {}", err))
    }
}
