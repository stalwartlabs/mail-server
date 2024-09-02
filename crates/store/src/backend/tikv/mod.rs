/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
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
const MAX_VALUE_SIZE: usize = 131072;
const MAX_CHUNKED_SIZED: usize = MAX_VALUE_SIZE * (1 + 256);
const MAX_SCAN_KEYS_SIZE: u32 = MAX_GRPC_MESSAGE_SIZE / MAX_ASSUMED_KEY_SIZE; // 8192
const MAX_SCAN_VALUES_SIZE: u32 = MAX_GRPC_MESSAGE_SIZE / MAX_VALUE_SIZE as u32; // 16

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
    read_trx_options: TransactionOptions,
    version: parking_lot::Mutex<Timestamp>,
    backoff: Backoff,
}

pub(crate) struct TimedTransaction {
    trx: Transaction,
    expires: Instant,
}

#[inline(always)]
fn into_error(error: TikvError) -> trc::Error {
    trc::StoreEvent::TikvError
        .reason(error.to_string())
}
