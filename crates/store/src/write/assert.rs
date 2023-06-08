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

use crate::Deserialize;

#[derive(Debug, Clone)]
pub struct HashedValue<T: Deserialize> {
    pub hash: u64,
    pub inner: T,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Hash(u64),
}

impl<T: Deserialize + Default> HashedValue<T> {
    pub fn take(&mut self) -> T {
        std::mem::take(&mut self.inner)
    }
}

pub trait ToAssertValue {
    fn to_assert_value(&self) -> AssertValue;
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
            AssertValue::U32(v) => {
                bytes.len() == std::mem::size_of::<u32>() && u32::deserialize(bytes).unwrap() == *v
            }
            AssertValue::U64(v) => {
                bytes.len() == std::mem::size_of::<u64>() && u64::deserialize(bytes).unwrap() == *v
            }
            AssertValue::Hash(v) => xxhash_rust::xxh3::xxh3_64(bytes) == *v,
        }
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
