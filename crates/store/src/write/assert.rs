use crate::Deserialize;

#[derive(Debug)]
pub struct HashedValue<T: Deserialize> {
    pub hash: u64,
    pub inner: T,
}

#[derive(Debug)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Hash(u64),
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
