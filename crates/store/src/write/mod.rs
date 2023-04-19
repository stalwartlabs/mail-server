use std::{collections::HashSet, slice::Iter, time::SystemTime};

use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::{
    fts::{builder::MAX_TOKEN_LENGTH, tokenizers::space::SpaceTokenizer},
    Deserialize, Serialize, BM_TAG, HASH_EXACT, TAG_ID, TAG_STATIC,
};

pub mod batch;
pub mod key;
pub mod log;

pub const F_VALUE: u32 = 1 << 0;
pub const F_INDEX: u32 = 1 << 1;
pub const F_BITMAP: u32 = 1 << 2;
pub const F_CLEAR: u32 = 1 << 3;

pub struct Batch {
    pub ops: Vec<Operation>,
}

#[derive(Debug)]
pub struct BatchBuilder {
    pub ops: Vec<Operation>,
}

#[derive(Debug)]
pub enum Operation {
    AccountId {
        account_id: u32,
    },
    Collection {
        collection: u8,
    },
    DocumentId {
        document_id: u32,
    },
    AssertValue {
        field: u8,
        family: u8,
        assert_value: AssertValue,
    },
    Value {
        field: u8,
        family: u8,
        set: Option<Vec<u8>>,
    },
    Index {
        field: u8,
        key: Vec<u8>,
        set: bool,
    },
    Bitmap {
        family: u8,
        field: u8,
        key: Vec<u8>,
        set: bool,
    },
    Acl {
        grant_account_id: u32,
        set: Option<Vec<u8>>,
    },
    Log {
        change_id: u64,
        collection: u8,
        set: Vec<u8>,
    },
}

#[derive(Debug)]
pub enum AssertValue {
    U32(u32),
    U64(u64),
    Hash(u64),
}

impl Serialize for u32 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for u64 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for u16 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for f64 {
    fn serialize(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Serialize for &str {
    fn serialize(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Serialize for String {
    fn serialize(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl Serialize for Vec<u8> {
    fn serialize(self) -> Vec<u8> {
        self
    }
}

impl Deserialize for String {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
            crate::Error::InternalError("Failed to deserialize u64".to_string())
        })?))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
            crate::Error::InternalError("Failed to deserialize u64".to_string())
        })?))
    }
}

pub trait SerializeInto {
    fn serialize_into(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeFrom: Sized {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl<T: SerializeInto> Serialize for Vec<T> {
    fn serialize(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len() * 4);
        bytes.push_leb128(self.len());
        for item in self {
            item.serialize_into(&mut bytes);
        }
        bytes
    }
}

impl SerializeInto for String {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(self.len());
        if !self.is_empty() {
            buf.extend_from_slice(self.as_bytes());
        }
    }
}

impl SerializeInto for u32 {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(*self);
    }
}

impl SerializeInto for u64 {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push_leb128(*self);
    }
}

impl DeserializeFrom for u32 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for u64 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for String {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let len: usize = bytes.next_leb128()?;
        let mut s = Vec::with_capacity(len);
        for _ in 0..len {
            s.push(*bytes.next()?);
        }
        String::from_utf8(s).ok()
    }
}

impl<T: DeserializeFrom + Sync + Send> Deserialize for Vec<T> {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| crate::Error::InternalError("Failed to deserialize Vec".to_string()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(T::deserialize_from(&mut bytes).ok_or_else(|| {
                crate::Error::InternalError("Failed to deserialize Vec".to_string())
            })?);
        }
        Ok(list)
    }
}

trait HasFlag {
    fn has_flag(&self, flag: u32) -> bool;
}

impl HasFlag for u32 {
    #[inline(always)]
    fn has_flag(&self, flag: u32) -> bool {
        self & flag == flag
    }
}

pub trait ToBitmaps {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool);
}

impl ToBitmaps for &str {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        let mut tokens = HashSet::new();

        for token in SpaceTokenizer::new(self, MAX_TOKEN_LENGTH) {
            tokens.insert(token);
        }

        for token in tokens {
            ops.push(Operation::hash(&token, HASH_EXACT, field, set));
        }
    }
}

impl ToBitmaps for String {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        self.as_str().to_bitmaps(ops, field, set)
    }
}

impl ToBitmaps for u32 {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            family: BM_TAG | TAG_ID,
            field,
            key: self.serialize(),
            set,
        });
    }
}

impl ToBitmaps for u64 {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        ops.push(Operation::Bitmap {
            family: BM_TAG | TAG_ID,
            field,
            key: (*self as u32).serialize(),
            set,
        });
    }
}

impl ToBitmaps for f64 {
    fn to_bitmaps(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl<T: ToBitmaps> ToBitmaps for Vec<T> {
    fn to_bitmaps(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        for item in self {
            item.to_bitmaps(ops, field, set);
        }
    }
}

pub trait BitmapFamily {
    fn family(&self) -> u8;
}

impl BitmapFamily for () {
    fn family(&self) -> u8 {
        BM_TAG | TAG_STATIC
    }
}

impl BitmapFamily for u32 {
    fn family(&self) -> u8 {
        BM_TAG | TAG_ID
    }
}

impl Serialize for () {
    fn serialize(self) -> Vec<u8> {
        Vec::with_capacity(0)
    }
}

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()>;
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

impl ToAssertValue for &[u8] {
    fn to_assert_value(&self) -> AssertValue {
        AssertValue::Hash(xxhash_rust::xxh3::xxh3_64(self))
    }
}

impl ToAssertValue for Vec<u8> {
    fn to_assert_value(&self) -> AssertValue {
        self.as_slice().to_assert_value()
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

#[inline(always)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
