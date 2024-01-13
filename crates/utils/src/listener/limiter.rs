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
    time::SystemTime,
};

use crate::config::Rate;

#[derive(Debug)]
pub struct RateLimiter {
    next_refill: AtomicU64,
    used_tokens: AtomicU64,
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
    pub fn new(rate: &Rate) -> Self {
        RateLimiter {
            next_refill: (now() + rate.period.as_secs()).into(),
            used_tokens: 0.into(),
        }
    }

    pub fn is_allowed(&self, rate: &Rate) -> bool {
        // Check rate limit
        if self.used_tokens.fetch_add(1, Ordering::Relaxed) < rate.requests {
            true
        } else {
            let now = now();
            if self.next_refill.load(Ordering::Relaxed) <= now {
                self.next_refill
                    .store(now + rate.period.as_secs(), Ordering::Relaxed);
                self.used_tokens.store(1, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
    }

    pub fn is_allowed_soft(&self, rate: &Rate) -> bool {
        self.used_tokens.load(Ordering::Relaxed) < rate.requests
            || self.next_refill.load(Ordering::Relaxed) <= now()
    }

    pub fn secs_to_refill(&self) -> u64 {
        self.next_refill
            .load(Ordering::Relaxed)
            .saturating_sub(now())
    }

    pub fn is_active(&self) -> bool {
        self.next_refill.load(Ordering::Relaxed) > now()
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

impl InFlight {
    pub fn num_concurrent(&self) -> u64 {
        self.concurrent.load(Ordering::Relaxed)
    }
}

fn now() -> u64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs()
}
