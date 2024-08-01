/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use foundationdb::{api::NetworkAutoStop, Database, FdbError, Transaction};

pub mod blob;
pub mod main;
pub mod read;
pub mod write;

const MAX_VALUE_SIZE: usize = 100000;
pub const TRANSACTION_EXPIRY: Duration = Duration::from_secs(1);
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(4);

#[allow(dead_code)]
pub struct FdbStore {
    db: Database,
    guard: NetworkAutoStop,
    version: parking_lot::Mutex<ReadVersion>,
}

pub(crate) struct TimedTransaction {
    trx: Transaction,
    expires: Instant,
}

pub(crate) struct ReadVersion {
    version: i64,
    expires: Instant,
}

impl ReadVersion {
    pub fn new(version: i64) -> Self {
        Self {
            version,
            expires: Instant::now() + TRANSACTION_EXPIRY,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires < Instant::now()
    }
}

impl Default for ReadVersion {
    fn default() -> Self {
        Self {
            version: 0,
            expires: Instant::now(),
        }
    }
}

impl AsRef<Transaction> for TimedTransaction {
    fn as_ref(&self) -> &Transaction {
        &self.trx
    }
}

impl TimedTransaction {
    pub fn new(trx: Transaction) -> Self {
        Self {
            trx,
            expires: Instant::now() + TRANSACTION_TIMEOUT,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires < Instant::now()
    }
}

#[inline(always)]
fn into_error(error: FdbError) -> trc::Error {
    trc::StoreEvent::FoundationdbError
        .reason(error.message())
        .ctx(trc::Key::Code, error.code())
}
