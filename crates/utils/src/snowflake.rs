/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

pub struct SnowflakeIdGenerator {
    epoch: SystemTime,
    node_id: u64,
    sequence: AtomicU64,
}

const SEQUENCE_LEN: u64 = 12;
const NODE_ID_LEN: u64 = 9;

const SEQUENCE_MASK: u64 = (1 << SEQUENCE_LEN) - 1;
const NODE_ID_MASK: u64 = (1 << NODE_ID_LEN) - 1;

impl SnowflakeIdGenerator {
    pub fn new() -> Self {
        Self::with_node_id(rand::random::<u64>())
    }

    pub fn with_node_id(node_id: u64) -> Self {
        Self {
            epoch: SystemTime::UNIX_EPOCH + Duration::from_secs(1632280000), // 52 years after UNIX_EPOCH
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

    #[inline(always)]
    pub fn generate(&self) -> Option<u64> {
        let elapsed = self.epoch.elapsed().ok()?.as_millis() as u64;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);

        (elapsed << (SEQUENCE_LEN + NODE_ID_LEN)
            | (self.node_id & NODE_ID_MASK) << SEQUENCE_LEN
            | (sequence & SEQUENCE_MASK))
            .into()
    }
}

impl Default for SnowflakeIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}
