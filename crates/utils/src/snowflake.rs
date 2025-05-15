/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

#[derive(Debug)]
pub struct SnowflakeIdGenerator {
    epoch: SystemTime,
    node_id: u64,
    sequence: AtomicU64,
}

pub struct HlcTimestamp;

const SEQUENCE_LEN: u64 = 12;
const NODE_ID_LEN: u64 = 9;

const SEQUENCE_MASK: u64 = (1 << SEQUENCE_LEN) - 1;
const NODE_ID_MASK: u64 = (1 << NODE_ID_LEN) - 1;

const DEFAULT_EPOCH: u64 = 1632280000; // 52 years after UNIX_EPOCH
const DEFAULT_EPOCH_MS: u128 = (DEFAULT_EPOCH as u128) * 1000; // 52 years after UNIX_EPOCH in milliseconds

const MAX_CLOCK_DRIFT: i64 = 2000; // 2 seconds

static LOGICAL_TIME: AtomicU64 = AtomicU64::new(0);
static CHANGE_SEQ: AtomicU64 = AtomicU64::new(0);
static NODE_MUM: LazyLock<u16> = LazyLock::new(|| CHANGE_SEQ.swap(0, Ordering::Relaxed) as u16);

/*

ID characteristics:

- 43 bits for milliseconds since January 1st, 2022: 2^43 / (1000 * 60 * 60 * 24 * 365) = 278.92 years (from year 2022 until 2300)
- 9 bits for a node id: 2^9 = 512 nodes
- 12 bits for a sequence number: 2^12 = 4096 ids per millisecond

*/

impl SnowflakeIdGenerator {
    pub fn new() -> Self {
        Self::with_node_id(rand::random::<u64>())
    }

    pub fn from_duration(period: Duration) -> Option<u64> {
        (SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_EPOCH))
            .elapsed()
            .ok()
            .and_then(|elapsed| elapsed.checked_sub(period))
            .map(|elapsed| (elapsed.as_millis() as u64) << (SEQUENCE_LEN + NODE_ID_LEN))
    }

    pub fn from_timestamp(timestamp: u64) -> Option<u64> {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|now| now.as_secs().checked_sub(timestamp))
            .and_then(|diff| Self::from_duration(Duration::from_secs(diff)))
    }

    pub fn with_node_id(node_id: u64) -> Self {
        Self {
            epoch: SystemTime::UNIX_EPOCH + Duration::from_secs(DEFAULT_EPOCH), // 52 years after UNIX_EPOCH
            node_id,
            sequence: 0.into(),
        }
    }

    #[inline(always)]
    pub fn past_id(&self, period: Duration) -> Option<u64> {
        self.epoch
            .elapsed()
            .ok()
            .and_then(|elapsed| elapsed.checked_sub(period))
            .map(|elapsed| (elapsed.as_millis() as u64) << (SEQUENCE_LEN + NODE_ID_LEN))
    }

    pub fn is_valid(&self) -> bool {
        self.epoch.elapsed().is_ok()
    }

    #[inline(always)]
    pub fn generate(&self) -> u64 {
        let elapsed = self
            .epoch
            .elapsed()
            .map(|e| e.as_millis())
            .unwrap_or_default() as u64;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) & SEQUENCE_MASK;

        (elapsed << (SEQUENCE_LEN + NODE_ID_LEN))
            | (sequence << NODE_ID_LEN)
            | (self.node_id & NODE_ID_MASK)
    }
}

impl HlcTimestamp {
    pub fn init(node_number: u16) {
        CHANGE_SEQ.store(node_number as u64, Ordering::Relaxed);
    }

    pub fn update_clock_from_remote_timestamp(timestamp: u64) -> Result<i64, i64> {
        let remote_clock = timestamp >> (SEQUENCE_LEN + NODE_ID_LEN);
        let local_elapsed = SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|e| e.as_millis())
            .unwrap_or_default()
            .saturating_sub(DEFAULT_EPOCH_MS) as u64;
        let diff = remote_clock as i64 - local_elapsed as i64;
        if diff > 0 {
            if diff < MAX_CLOCK_DRIFT {
                LOGICAL_TIME.fetch_max(remote_clock, Ordering::SeqCst);
                Ok(diff)
            } else {
                Err(diff)
            }
        } else {
            Ok(diff)
        }
    }

    pub fn generate() -> u64 {
        let node_id = *NODE_MUM;
        let elapsed = SystemTime::UNIX_EPOCH
            .elapsed()
            .map(|e| e.as_millis())
            .unwrap_or_default()
            .saturating_sub(DEFAULT_EPOCH_MS) as u64;
        let elapsed = LOGICAL_TIME
            .fetch_max(elapsed, Ordering::SeqCst)
            .max(elapsed);
        let sequence = CHANGE_SEQ.fetch_add(1, Ordering::Relaxed) & SEQUENCE_MASK;

        (elapsed << (SEQUENCE_LEN + NODE_ID_LEN))
            | (sequence << NODE_ID_LEN)
            | (node_id as u64 & NODE_ID_MASK)
    }
}

impl Default for SnowflakeIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SnowflakeIdGenerator {
    fn clone(&self) -> Self {
        Self {
            epoch: self.epoch,
            node_id: self.node_id,
            sequence: 0.into(),
        }
    }
}
