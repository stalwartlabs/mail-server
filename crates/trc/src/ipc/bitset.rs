/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{USIZE_BITS, USIZE_BITS_MASK};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitset<const N: usize>(pub(crate) [usize; N]);

impl<const N: usize> Bitset<N> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self([0; N])
    }

    pub const fn all() -> Self {
        Self([usize::MAX; N])
    }

    #[inline(always)]
    pub fn set(&mut self, index: impl Into<usize>) {
        let index = index.into();
        self.0[index / USIZE_BITS] |= 1 << (index & USIZE_BITS_MASK);
    }

    #[inline(always)]
    pub fn clear(&mut self, index: impl Into<usize>) {
        let index = index.into();
        self.0[index / USIZE_BITS] &= !(1 << (index & USIZE_BITS_MASK));
    }

    #[inline(always)]
    pub fn get(&self, index: impl Into<usize>) -> bool {
        let index = index.into();
        self.0[index / USIZE_BITS] & (1 << (index & USIZE_BITS_MASK)) != 0
    }

    pub fn union(&mut self, other: &Self) {
        for i in 0..N {
            self.0[i] |= other.0[i];
        }
    }

    pub fn intersection(&mut self, other: &Self) {
        for i in 0..N {
            self.0[i] &= other.0[i];
        }
    }

    pub fn difference(&mut self, other: &Self) {
        for i in 0..N {
            self.0[i] &= !other.0[i];
        }
    }

    pub fn clear_all(&mut self) {
        for i in 0..N {
            self.0[i] = 0;
        }
    }

    pub fn is_empty(&self) -> bool {
        for i in 0..N {
            if self.0[i] != 0 {
                return false;
            }
        }
        true
    }

    pub fn inner(&self) -> &[usize; N] {
        &self.0
    }
}

impl<const N: usize> Default for Bitset<N> {
    fn default() -> Self {
        Self::new()
    }
}
