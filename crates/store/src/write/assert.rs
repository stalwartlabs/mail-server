/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Archive, ArchiveVersion};
use crate::{U32_LEN, U64_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Archive(ArchiveVersion),
    Some,
    None,
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
        AssertValue::Archive(self.version)
    }
}

impl<T> ToAssertValue for &Archive<T> {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Archive(self.version)
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
            AssertValue::Archive(v) => match v {
                ArchiveVersion::Versioned { hash, .. } => bytes
                    .get(bytes.len() - U32_LEN - U64_LEN - 1..bytes.len() - U64_LEN - 1)
                    .is_some_and(|b| b == hash.to_be_bytes()),
                ArchiveVersion::Hashed { hash } => bytes
                    .get(bytes.len() - U32_LEN - 1..bytes.len() - 1)
                    .is_some_and(|b| b == hash.to_be_bytes()),
                ArchiveVersion::Unversioned => false,
            },
            AssertValue::None => false,
            AssertValue::Some => true,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, AssertValue::None)
    }
}
