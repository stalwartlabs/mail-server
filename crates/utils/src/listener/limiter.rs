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

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct RateLimiter {
    pub max_requests: u64,
    pub max_interval: Duration,
    last_refill: Instant,
    tokens: u64,
}

#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    pub max_concurrent: u64,
    pub concurrent: Arc<AtomicU64>,
}

#[derive(Default)]
pub struct InFlight {
    concurrent: Arc<AtomicU64>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl RateLimiter {
    pub fn new(max_requests: u64, max_interval: Duration) -> Self {
        RateLimiter {
            max_requests,
            max_interval,
            last_refill: Instant::now(),
            tokens: max_requests,
        }
    }

    pub fn is_allowed(&mut self) -> bool {
        // Check rate limit
        if self.last_refill.elapsed() >= self.max_interval {
            self.last_refill = Instant::now();
            self.tokens = self.max_requests;
        }

        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    pub fn retry_at(&self) -> Instant {
        Instant::now()
            + (self
                .max_interval
                .checked_sub(self.last_refill.elapsed())
                .unwrap_or_default())
    }

    pub fn elapsed(&self) -> Duration {
        self.last_refill.elapsed()
    }

    pub fn reset(&mut self) {
        self.last_refill = Instant::now();
        self.tokens = self.max_requests;
    }

    pub fn is_active(&self) -> bool {
        self.tokens < self.max_requests || self.last_refill.elapsed() < self.max_interval
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter {
            max_concurrent,
            concurrent: Arc::new(0.into()),
        }
    }

    pub fn is_allowed(&self) -> Option<InFlight> {
        if self.concurrent.load(Ordering::Relaxed) < self.max_concurrent {
            // Return in-flight request
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            Some(InFlight {
                concurrent: self.concurrent.clone(),
            })
        } else {
            None
        }
    }

    pub fn check_is_allowed(&self) -> bool {
        self.concurrent.load(Ordering::Relaxed) < self.max_concurrent
    }

    pub fn is_active(&self) -> bool {
        self.concurrent.load(Ordering::Relaxed) > 0
    }
}
