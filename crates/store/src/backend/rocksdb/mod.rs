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
