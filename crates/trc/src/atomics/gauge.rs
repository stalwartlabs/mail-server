/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicU64, Ordering};

use crate::MetricType;

pub struct AtomicGauge {
    id: MetricType,
    value: AtomicU64,
}

impl AtomicGauge {
    pub const fn new(id: MetricType) -> Self {
        Self {
            id,
            value: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn decrement(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn subtract(&self, value: u64) {
        self.value.fetch_sub(value, Ordering::Relaxed);
    }

    pub fn id(&self) -> MetricType {
        self.id
    }
}
