/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};
use tikv_client::{TransactionClient, Transaction, Error as TikvError, Snapshot, Value, Key, Timestamp, RawClient, TransactionOptions, Backoff, KvPair, BoundRange};
use crate::write::key::KeySerializer;

pub mod blob;
pub mod main;
pub mod read;
pub mod write;


// https://github.com/tikv/tikv/issues/7272#issuecomment-604841372

// Default limit is 4194304 bytes
const MAX_KEY_SIZE: u32 = 4 * 1024;
// Default limit is 4194304 bytes. Let's use half of that as a base to be safe (2097152 bytes).
// Then, 2097152
const MAX_GRPC_MESSAGE_SIZE: u32 = 2097152;
const MAX_ASSUMED_KEY_SIZE: u32 = 256;
const MAX_VALUE_SIZE: u32 = 131072;
const MAX_SCAN_KEYS_SIZE: u32 = MAX_GRPC_MESSAGE_SIZE / MAX_ASSUMED_KEY_SIZE; // 8192
const MAX_SCAN_VALUES_SIZE: u32 = MAX_GRPC_MESSAGE_SIZE / MAX_VALUE_SIZE; // 16

// Preparation for API v2
// RFC: https://github.com/tikv/rfcs/blob/master/text/0069-api-v2.md
const MODE_PREFIX_TXN_KV: u8 = b'x';
const MODE_PREFIX_RAW_KV: u8 = b'x';

pub const TRANSACTION_EXPIRY: Duration = Duration::from_secs(1);
pub const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(4);

#[allow(dead_code)]
pub struct TikvStore {
    trx_client: TransactionClient,
    write_trx_options: TransactionOptions,
    raw_client: RawClient,
    raw_backoff: Backoff,
    api_v2: bool,
    keyspace: [u8; 3], // Keyspace is fixed-length of 3 bytes in network byte order.
    version: parking_lot::Mutex<ReadVersion>,
}

impl TikvStore {
    fn new_key_serializer(&self, capacity: usize, raw: bool) -> KeySerializer {
        if self.api_v2 {
            // We don't care about compatibility anymore
            KeySerializer::new(capacity)
        } else {
            let mode_prefix = raw.then(|| MODE_PREFIX_RAW_KV).unwrap_or_else(|| MODE_PREFIX_TXN_KV);
            // Capacity = mode_prefix length + keyspace length + capacity
            KeySerializer::new(1 + 3 + capacity)
                .write(mode_prefix)
                .write(self.keyspace.as_slice())
        }
    }

    fn remove_prefix<'a>(&self, key: &'a [u8]) -> &'a [u8] {
        if self.api_v2 {
            key
        } else {
            &key[4..]
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
