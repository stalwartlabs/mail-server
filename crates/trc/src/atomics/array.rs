/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub struct AtomicU32Array<const N: usize>([AtomicU32; N]);
pub struct AtomicU64Array<const N: usize>([AtomicU64; N]);

impl<const N: usize> AtomicU32Array<N> {
    #[allow(clippy::new_without_default)]
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        Self({
            const INIT: AtomicU32 = AtomicU32::new(0);
            let mut array = [INIT; N];
            let mut i = 0;
            while i < N {
                array[i] = AtomicU32::new(0);
                i += 1;
            }
            array
        })
    }

    #[inline(always)]
    pub fn get(&self, index: usize) -> u32 {
        self.0[index].load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn set(&self, index: usize, value: u32) {
        self.0[index].store(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add(&self, index: usize, value: u32) {
        self.0[index].fetch_add(value, Ordering::Relaxed);
    }

    pub fn inner(&self) -> &[AtomicU32; N] {
        &self.0
    }
}

impl<const N: usize> AtomicU64Array<N> {
    #[allow(clippy::new_without_default)]
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        Self({
            const INIT: AtomicU64 = AtomicU64::new(0);
            let mut array = [INIT; N];
            let mut i = 0;
            while i < N {
                array[i] = AtomicU64::new(0);
                i += 1;
            }
            array
        })
    }

    #[inline(always)]
    pub fn get(&self, index: usize) -> u64 {
        self.0[index].load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn set(&self, index: usize, value: u64) {
        self.0[index].store(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add(&self, index: usize, value: u64) {
        self.0[index].fetch_add(value, Ordering::Relaxed);
    }

    pub fn inner(&self) -> &[AtomicU64; N] {
        &self.0
    }
}
