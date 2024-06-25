/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use rocksdb::{BoundColumnFamily, MultiThreaded, OptimisticTransactionDB};

use crate::{SUBSPACE_BLOBS, SUBSPACE_INDEXES, SUBSPACE_LOGS};

pub mod blob;
pub mod main;
pub mod read;
pub mod write;

static CF_LOGS: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_LOGS]) };
static CF_INDEXES: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_INDEXES]) };
static CF_BLOBS: &str = unsafe { std::str::from_utf8_unchecked(&[SUBSPACE_BLOBS]) };

impl From<rocksdb::Error> for crate::Error {
    fn from(value: rocksdb::Error) -> Self {
        Self::InternalError(format!("RocksDB error: {}", value))
    }
}

pub(crate) trait CfHandle {
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>>;
}

impl CfHandle for OptimisticTransactionDB<MultiThreaded> {
    #[inline(always)]
    fn subspace_handle(&self, subspace: u8) -> Arc<BoundColumnFamily<'_>> {
        self.cf_handle(unsafe { std::str::from_utf8_unchecked(&[subspace]) })
            .unwrap()
    }
}

pub struct RocksDbStore {
    db: Arc<OptimisticTransactionDB<MultiThreaded>>,
    worker_pool: rayon::ThreadPool,
}
