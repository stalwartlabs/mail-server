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

#[cfg(feature = "elastic")]
pub mod elastic;
#[cfg(feature = "foundation")]
pub mod foundationdb;
pub mod fs;
pub mod memory;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "rocks")]
pub mod rocksdb;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub const MAX_TOKEN_LENGTH: usize = (u8::MAX >> 1) as usize;
pub const MAX_TOKEN_MASK: usize = MAX_TOKEN_LENGTH - 1;

#[cfg(feature = "test_mode")]
pub static ID_ASSIGNMENT_EXPIRY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(60 * 60); // seconds
#[cfg(not(feature = "test_mode"))]
pub const ID_ASSIGNMENT_EXPIRY: u64 = 60 * 60; // seconds

impl From<std::io::Error> for crate::Error {
    fn from(err: std::io::Error) -> Self {
        Self::InternalError(format!("IO error: {}", err))
    }
}

#[allow(dead_code)]
fn deserialize_i64_le(bytes: &[u8]) -> crate::Result<i64> {
    Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
        crate::Error::InternalError("Failed to deserialize i64 value.".to_string())
    })?))
}
