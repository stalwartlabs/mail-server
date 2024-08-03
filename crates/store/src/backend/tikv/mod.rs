/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};
use tikv_client::{TransactionClient, Transaction, Error as TikvError, Snapshot, Value, Key};

pub mod blob;
pub mod main;
pub mod read;
pub mod write;


// https://github.com/tikv/tikv/issues/7272#issuecomment-604841372

const MAX_KEY_SIZE: usize = 4 * 1024;
const MAX_VALUE_SIZE: usize = 100000;
const MAX_KEYS: u32 = 100000;
const MAX_KV_PAIRS: u32 = 50000;
pub const TRANSACTION_EXPIRY: Duration = Duration::from_secs(1);
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(4);

#[allow(dead_code)]
pub struct TikvStore {
    client: TransactionClient,
    version: parking_lot::Mutex<ReadVersion>,
}

pub(crate) enum ReadTransaction {
    Transaction(Transaction),
    Snapshot(Snapshot)
}

impl ReadTransaction {
    pub(crate) async fn get(&mut self, key: impl Into<Key>) -> trc::Result<Option<Value>> {
        match self {
            ReadTransaction::Transaction(trx) => {
                trx.get(key).await.map_err(into_error)
            }
            ReadTransaction::Snapshot(ss) => {
                ss.get(key).await.map_err(into_error)
            }
        }
    }
}

impl From<Transaction> for ReadTransaction {
    fn from(value: Transaction) -> Self {
        Self::Transaction(value)
    }
}

impl From<Snapshot> for ReadTransaction {
    fn from(value: Snapshot) -> Self {
        Self::Snapshot(value)
    }
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
fn into_error(error: TikvError) -> trc::Error {
    trc::StoreEvent::FoundationdbError
        .reason(error.to_string())
}
