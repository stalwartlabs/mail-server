/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
