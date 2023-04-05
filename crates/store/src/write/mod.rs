use std::{collections::HashSet, time::SystemTime};

use crate::{
    fts::{builder::MAX_TOKEN_LENGTH, tokenizers::space::SpaceTokenizer},
    Deserialize, Serialize, BM_TAG, HASH_EXACT, TAG_ID, TAG_STATIC, TAG_TEXT,
};

pub mod batch;
pub mod key;
pub mod log;

pub const F_VALUE: u32 = 1 << 0;
pub const F_INDEX: u32 = 1 << 1;
pub const F_TOKENIZE: u32 = 1 << 2;
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
    Blob {
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

trait HasFlag {
    fn has_flag(&self, flag: u32) -> bool;
}

impl HasFlag for u32 {
    #[inline(always)]
    fn has_flag(&self, flag: u32) -> bool {
        self & flag == flag
    }
}

pub trait Tokenize {
    fn tokenize(&self, ops: &mut Vec<Operation>, field: u8, set: bool);
}

impl Tokenize for &str {
    fn tokenize(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        let mut tokens = HashSet::new();

        for token in SpaceTokenizer::new(self, MAX_TOKEN_LENGTH) {
            tokens.insert(token);
        }

        for token in tokens {
            ops.push(Operation::hash(&token, HASH_EXACT, field, set));
        }
    }
}

impl Tokenize for String {
    fn tokenize(&self, ops: &mut Vec<Operation>, field: u8, set: bool) {
        self.as_str().tokenize(ops, field, set)
    }
}

impl Tokenize for u32 {
    fn tokenize(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl Tokenize for u64 {
    fn tokenize(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

impl Tokenize for f64 {
    fn tokenize(&self, _ops: &mut Vec<Operation>, _field: u8, _set: bool) {
        unreachable!()
    }
}

pub trait IntoBitmap {
    fn into_bitmap(self) -> (Vec<u8>, u8);
}

impl IntoBitmap for () {
    fn into_bitmap(self) -> (Vec<u8>, u8) {
        (vec![], BM_TAG | TAG_STATIC)
    }
}

impl IntoBitmap for u32 {
    fn into_bitmap(self) -> (Vec<u8>, u8) {
        (self.serialize(), BM_TAG | TAG_ID)
    }
}

impl IntoBitmap for String {
    fn into_bitmap(self) -> (Vec<u8>, u8) {
        (self.serialize(), BM_TAG | TAG_TEXT)
    }
}

impl IntoBitmap for &str {
    fn into_bitmap(self) -> (Vec<u8>, u8) {
        (self.serialize(), BM_TAG | TAG_TEXT)
    }
}

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()>;
}

#[inline(always)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
