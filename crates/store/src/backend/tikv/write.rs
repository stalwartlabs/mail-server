/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    time::{Duration, Instant},
};

use tikv_client::{
    Transaction
};
use rand::Rng;
use roaring::RoaringBitmap;

use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        AssignedIds, Batch, BitmapClass, Operation, RandomAvailableId, ValueOp,
        MAX_COMMIT_ATTEMPTS, MAX_COMMIT_TIME,
    },
    BitmapKey, IndexKey, Key, LogKey, SUBSPACE_COUNTER, SUBSPACE_QUOTA, U32_LEN, WITH_SUBSPACE,
};

use super::{
    into_error,
    read::{read_chunked_value, ChunkedValue},
    TikvStore, ReadVersion, MAX_VALUE_SIZE,
};

impl TikvStore {
    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        todo!()
    }

    pub(crate) async fn commit(&self, trx: Transaction, will_retry: bool) -> trc::Result<bool> {
        todo!()
    }
    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        todo!()
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        todo!()
    }
}
