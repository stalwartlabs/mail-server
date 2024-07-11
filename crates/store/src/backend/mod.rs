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

#[allow(dead_code)]
fn deserialize_i64_le(key: &[u8], bytes: &[u8]) -> trc::Result<i64> {
    Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
        trc::Error::corrupted_key(key, bytes.into(), trc::location!())
    })?))
}
