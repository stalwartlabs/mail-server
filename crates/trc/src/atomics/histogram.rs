/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicU64, Ordering};

use crate::MetricType;

use super::array::AtomicU64Array;

pub struct AtomicHistogram<const N: usize> {
    id: MetricType,
    buckets: AtomicU64Array<N>,
    upper_bounds: [u64; N],
    sum: AtomicU64,
    count: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
}

impl<const N: usize> AtomicHistogram<N> {
    pub const fn new(id: MetricType, upper_bounds: [u64; N]) -> Self {
        Self {
            buckets: AtomicU64Array::new(),
            upper_bounds,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
            id,
        }
    }

    pub fn observe(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.min.fetch_min(value, Ordering::Relaxed);
        self.max.fetch_max(value, Ordering::Relaxed);

        for (idx, upper_bound) in self.upper_bounds.iter().enumerate() {
            if value < *upper_bound {
                self.buckets.add(idx, value);
                return;
            }
        }

        unreachable!()
    }

    pub fn id(&self) -> MetricType {
        self.id
    }

    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn average(&self) -> f64 {
        let sum = self.sum();
        let count = self.count();
        if count > 0 {
            sum as f64 / count as f64
        } else {
            0.0
        }
    }

    pub fn min(&self) -> Option<u64> {
        let min = self.min.load(Ordering::Relaxed);
        if min != u64::MAX {
            Some(min)
        } else {
            None
        }
    }

    pub fn max(&self) -> Option<u64> {
        let max = self.max.load(Ordering::Relaxed);
        if max != 0 {
            Some(max)
        } else {
            None
        }
    }

    pub fn buckets_iter(&self) -> impl IntoIterator<Item = u64> + '_ {
        self.buckets
            .inner()
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
    }

    pub fn buckets_vec(&self) -> Vec<u64> {
        let mut vec = Vec::with_capacity(N);
        for bucket in self.buckets.inner().iter() {
            vec.push(bucket.load(Ordering::Relaxed));
        }
        vec
    }

    pub fn buckets_len(&self) -> usize {
        N
    }

    pub fn upper_bounds_iter(&self) -> impl IntoIterator<Item = u64> + '_ {
        self.upper_bounds.iter().copied()
    }

    pub fn upper_bounds_vec(&self) -> Vec<f64> {
        let mut vec = Vec::with_capacity(N - 1);
        for upper_bound in self.upper_bounds.iter().take(N - 1) {
            vec.push(*upper_bound as f64);
        }
        vec
    }

    pub fn is_active(&self) -> bool {
        self.count.load(Ordering::Relaxed) > 0
    }

    pub const fn new_message_sizes(id: MetricType) -> AtomicHistogram<12> {
        AtomicHistogram::new(
            id,
            [
                500,         // 500 bytes
                1_000,       // 1 KB
                10_000,      // 10 KB
                100_000,     // 100 KB
                1_000_000,   // 1 MB
                5_000_000,   // 5 MB
                10_000_000,  // 10 MB
                25_000_000,  // 25 MB
                50_000_000,  // 50 MB
                100_000_000, // 100 MB
                500_000_000, // 500 MB
                u64::MAX,    // Catch-all for any larger sizes
            ],
        )
    }

    pub const fn new_short_durations(id: MetricType) -> AtomicHistogram<12> {
        AtomicHistogram::new(
            id,
            [
                5,        // 5 milliseconds
                10,       // 10 milliseconds
                50,       // 50 milliseconds
                100,      // 100 milliseconds
                500,      // 0.5 seconds
                1_000,    // 1 second
                2_000,    // 2 seconds
                5_000,    // 5 seconds
                10_000,   // 10 seconds
                30_000,   // 30 seconds
                60_000,   // 1 minute
                u64::MAX, // Catch-all for any longer durations
            ],
        )
    }

    pub const fn new_medium_durations(id: MetricType) -> AtomicHistogram<12> {
        AtomicHistogram::new(
            id,
            [
                250,
                500,
                1_000,
                5_000,
                10_000, // For quick connections (seconds)
                60_000,
                (60 * 5) * 1_000,
                (60 * 10) * 1_000,
                (60 * 30) * 1_000, // For medium-length connections (minutes)
                (60 * 60) * 1_000,
                (60 * 60 * 5) * 1_000,
                u64::MAX, // For extreme cases (8 hours and 1 day)
            ],
        )
    }

    pub const fn new_long_durations(id: MetricType) -> AtomicHistogram<12> {
        AtomicHistogram::new(
            id,
            [
                1_000,       // 1 second
                30_000,      // 30 seconds
                300_000,     // 5 minutes
                600_000,     // 10 minutes
                1_800_000,   // 30 minutes
                3_600_000,   // 1 hour
                14_400_000,  // 5 hours
                28_800_000,  // 8 hours
                43_200_000,  // 12 hours
                86_400_000,  // 1 day
                604_800_000, // 1 week
                u64::MAX,    // Catch-all for any longer durations
            ],
        )
    }
}
