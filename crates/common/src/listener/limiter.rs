/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone)]
pub struct ConcurrencyLimiter {
    pub max_concurrent: u64,
    pub concurrent: Arc<AtomicU64>,
}

#[derive(Default)]
pub struct InFlight {
    concurrent: Arc<AtomicU64>,
}

pub enum LimiterResult {
    Allowed(InFlight),
    Forbidden,
    Disabled,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.concurrent.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter {
            max_concurrent,
            concurrent: Arc::new(0.into()),
        }
    }

    pub fn is_allowed(&self) -> LimiterResult {
        if self.concurrent.load(Ordering::Relaxed) < self.max_concurrent {
            // Return in-flight request
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            LimiterResult::Allowed(InFlight {
                concurrent: self.concurrent.clone(),
            })
        } else {
            LimiterResult::Forbidden
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

impl From<LimiterResult> for Option<InFlight> {
    fn from(result: LimiterResult) -> Self {
        match result {
            LimiterResult::Allowed(in_flight) => Some(in_flight),
            LimiterResult::Forbidden => None,
            LimiterResult::Disabled => Some(InFlight::default()),
        }
    }
}
