/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Deserialize, U32_LEN, U64_LEN};

use super::Archive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Hash(u64),
    Some,
    None,
}

#[derive(Debug, Clone)]
pub struct LegacyHashedValue<T: Deserialize> {
    pub hash: u64,
    pub inner: T,
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

impl<T> ToAssertValue for Archive<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::U32(self.hash)
    }
}

impl<T> ToAssertValue for &Archive<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::U32(self.hash)
    }
}

impl<T: Deserialize> ToAssertValue for LegacyHashedValue<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Hash(self.hash)
    }
}

impl<T: Deserialize> ToAssertValue for &LegacyHashedValue<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Hash(self.hash)
    }
}

impl AssertValue {
    pub fn matches(&self, bytes: &[u8]) -> bool {
        match self {
            AssertValue::U32(v) => bytes
                .get(bytes.len() - U32_LEN..)
                .is_some_and(|b| b == v.to_be_bytes()),

            AssertValue::U64(v) => bytes
                .get(bytes.len() - U64_LEN..)
                .is_some_and(|b| b == v.to_be_bytes()),
            AssertValue::Hash(v) => xxhash_rust::xxh3::xxh3_64(bytes) == *v,
            AssertValue::None => false,
            AssertValue::Some => true,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, AssertValue::None)
    }
}

impl<T: Deserialize> Deserialize for LegacyHashedValue<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(LegacyHashedValue {
            hash: xxhash_rust::xxh3::xxh3_64(bytes),
            inner: T::deserialize(bytes)?,
        })
    }
}
