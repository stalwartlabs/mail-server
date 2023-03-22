use std::collections::HashSet;

use crate::Serialize;

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

pub struct BatchBuilder {
    pub last_account_id: u32,
    pub last_document_id: u32,
    pub last_collection: u8,
    pub ops: Vec<Operation>,
}

pub enum Operation {
    WithContext {
        account_id: u32,
        document_id: u32,
        collection: u8,
    },
    Value {
        field: u8,
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
        to_account_id: u32,
        set: Option<Vec<u8>>,
    },
    Log {
        change_id: u64,
        changes: Vec<u8>,
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
    fn tokenize(&self) -> HashSet<Vec<u8>>;
}

impl Tokenize for &str {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        let mut tokens = HashSet::new();
        let mut token = String::new();

        for ch in self.chars() {
            if ch.is_alphanumeric() {
                if ch.is_uppercase() {
                    token.push(ch.to_lowercase().next().unwrap());
                } else {
                    token.push(ch);
                }
            } else if !token.is_empty() {
                tokens.insert(token.into_bytes());
                token = String::new();
            }
        }

        tokens
    }
}

impl Tokenize for String {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        self.as_str().tokenize()
    }
}

impl Tokenize for u32 {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        unreachable!()
    }
}

impl Tokenize for u64 {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        unreachable!()
    }
}

impl Tokenize for f64 {
    fn tokenize(&self) -> HashSet<Vec<u8>> {
        unreachable!()
    }
}

pub trait IntoBitmap {
    fn into_bitmap(self) -> (Vec<u8>, u8);
}

pub trait IntoOperations {
    fn build(self, batch: &mut BatchBuilder) -> crate::Result<()>;
}
