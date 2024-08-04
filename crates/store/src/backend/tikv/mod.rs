/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};
use tikv_client::{TransactionClient, Transaction, Error as TikvError, Snapshot, Value, Key, Timestamp, RawClient, TransactionOptions, Backoff};
use tikv_client::proto::kvrpcpb;
use tikv_client::proto::kvrpcpb::Mutation;
use crate::write::{AssignedIds, ValueOp};

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
    trx_client: TransactionClient,
    write_trx_options: TransactionOptions,
    raw_client: RawClient,
    raw_backoff: Backoff,
    version: parking_lot::Mutex<ReadVersion>,
}

// TODO: Remove
pub(crate) enum ReadTransaction<'db> {
    Transaction(&'db mut Transaction),
    Snapshot(&'db mut Snapshot)
}

impl<'a> ReadTransaction<'a> {
    pub(crate) async fn get(&'a mut self, key: impl Into<Key>) -> trc::Result<Option<Value>> {
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

pub(crate) struct TimedTransaction {
    trx: Transaction,
    expires: Instant,
}

pub(crate) struct ReadVersion {
    version: Timestamp,
    expires: Instant,
}

impl ReadVersion {
    pub fn new(version: Timestamp) -> Self {
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
            version: Timestamp::default(),
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
    trc::StoreEvent::TikvError
        .reason(error.to_string())
}
