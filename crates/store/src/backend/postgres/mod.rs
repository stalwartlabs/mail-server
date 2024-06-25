/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool_postgres::{Pool, PoolError};

pub mod blob;
pub mod lookup;
pub mod main;
pub mod read;
pub mod tls;
pub mod write;

pub struct PostgresStore {
    pub(crate) conn_pool: Pool,
}

impl From<PoolError> for crate::Error {
    fn from(err: PoolError) -> Self {
        Self::InternalError(format!("Connection pool error: {}", err))
    }
}

impl From<tokio_postgres::Error> for crate::Error {
    fn from(err: tokio_postgres::Error) -> Self {
        Self::InternalError(format!("PostgreSQL error: {}", err))
    }
}

#[inline(always)]
pub fn deserialize_bitmap(bytes: &[u8]) -> crate::Result<roaring::RoaringBitmap> {
    roaring::RoaringBitmap::deserialize_unchecked_from(bytes).map_err(|err| {
        crate::Error::InternalError(format!("Failed to deserialize bitmap: {}", err))
    })
}
