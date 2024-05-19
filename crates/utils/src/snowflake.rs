/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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
