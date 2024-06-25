/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Deserialize, U32_LEN, U64_LEN};

#[derive(Debug, Clone)]
pub struct HashedValue<T: Deserialize> {
    pub hash: u64,
    pub inner: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Hash(u64),
    Some,
    None,
}

impl<T: Deserialize + Default> HashedValue<T> {
    pub fn take(&mut self) -> T {
        std::mem::take(&mut self.inner)
    }
}

pub trait ToAssertValue {
    fn to_assert_value(&self) -> AssertValue;
}

impl ToAssertValue for AssertValue {
    fn to_assert_value(&self) -> AssertValue {
        *self
    }
}

impl ToAssertValue for () {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::None
    }
}

impl ToAssertValue for u64 {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::U64(*self)
    }
}

impl ToAssertValue for u32 {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::U32(*self)
    }
}

impl<T: Deserialize> ToAssertValue for HashedValue<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Hash(self.hash)
    }
}

impl<T: Deserialize> ToAssertValue for &HashedValue<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Hash(self.hash)
    }
}

impl AssertValue {
    pub fn matches(&self, bytes: &[u8]) -> bool {
        match self {
            AssertValue::U32(v) => bytes.len() == U32_LEN && u32::deserialize(bytes).unwrap() == *v,
            AssertValue::U64(v) => bytes.len() == U64_LEN && u64::deserialize(bytes).unwrap() == *v,
            AssertValue::Hash(v) => xxhash_rust::xxh3::xxh3_64(bytes) == *v,
            AssertValue::None => false,
            AssertValue::Some => true,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, AssertValue::None)
    }
}

impl<T: Deserialize> Deserialize for HashedValue<T> {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(HashedValue {
            hash: xxhash_rust::xxh3::xxh3_64(bytes),
            inner: T::deserialize(bytes)?,
        })
    }
}
