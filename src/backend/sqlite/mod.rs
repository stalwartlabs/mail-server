use crate::{
    write::key::KeySerializer, AclKey, BitmapKey, BlobKey, IndexKey, IndexKeyPrefix, LogKey,
    Serialize, ValueKey, BLOB_HASH_LEN,
};

pub mod id_assign;
pub mod main;
pub mod pool;
pub mod read;
pub mod write;

const WORD_SIZE_BITS: u32 = (WORD_SIZE * 8) as u32;
const WORD_SIZE: usize = std::mem::size_of::<u64>();
const WORDS_PER_BLOCK: u32 = 16;
pub const BITS_PER_BLOCK: u32 = WORD_SIZE_BITS * WORDS_PER_BLOCK;
const BITS_MASK: u32 = BITS_PER_BLOCK - 1;

impl<T: AsRef<[u8]>> Serialize for &IndexKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len() + 1)
            .write(self.account_id)
            .write(self.collection)
            .write(self.field)
            .write(key)
            .write(self.document_id)
            .finalize()
    }
}

impl Serialize for &IndexKeyPrefix {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>() + 1)
            .write(self.account_id)
            .write(self.collection)
            .write(self.field)
            .finalize()
    }
}

impl Serialize for &ValueKey {
    fn serialize(self) -> Vec<u8> {
        if self.family == 0 {
            KeySerializer::new(std::mem::size_of::<ValueKey>() + 1)
                .write_leb128(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(self.field)
                .finalize()
        } else {
            KeySerializer::new(std::mem::size_of::<ValueKey>() + 2)
                .write_leb128(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(u8::MAX)
                .write(self.family)
                .write(self.field)
                .finalize()
        }
    }
}

impl<T: AsRef<[u8]>> Serialize for &BitmapKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        KeySerializer::new(std::mem::size_of::<BitmapKey<T>>() + key.len() + 1)
            .write(self.account_id)
            .write(self.collection)
            .write(self.family)
            .write(self.field)
            .write(key)
            .write(self.block_num)
            .finalize()
    }
}

impl<T: AsRef<[u8]>> Serialize for &BlobKey<T> {
    fn serialize(self) -> Vec<u8> {
        let hash = self.hash.as_ref();
        KeySerializer::new(std::mem::size_of::<BlobKey<T>>() + BLOB_HASH_LEN + 1)
            .write(hash)
            .write_leb128(self.account_id)
            .write(self.collection)
            .write_leb128(self.document_id)
            .finalize()
    }
}

impl<T: AsRef<[u8]>> Serialize for BlobKey<T> {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Serialize for &AclKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<AclKey>() + 1)
            .write_leb128(self.grant_account_id)
            .write(u8::MAX)
            .write_leb128(self.to_account_id)
            .write(self.to_collection)
            .write_leb128(self.to_document_id)
            .finalize()
    }
}

impl Serialize for &LogKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<LogKey>() + 1)
            .write(self.account_id)
            .write(self.collection)
            .write(self.change_id)
            .finalize()
    }
}

impl From<r2d2::Error> for crate::Error {
    fn from(err: r2d2::Error) -> Self {
        Self::InternalError(format!("Connection pool error: {}", err))
    }
}

impl From<rusqlite::Error> for crate::Error {
    fn from(err: rusqlite::Error) -> Self {
        Self::InternalError(format!("SQLite error: {}", err))
    }
}

impl From<rusqlite::types::FromSqlError> for crate::Error {
    fn from(err: rusqlite::types::FromSqlError) -> Self {
        Self::InternalError(format!("SQLite error: {}", err))
    }
}
