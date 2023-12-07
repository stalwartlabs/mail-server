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
