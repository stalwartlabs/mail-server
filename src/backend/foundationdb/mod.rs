use foundationdb::FdbError;

use crate::{
    write::key::KeySerializer, AclKey, BitmapKey, BlobKey, Error, IndexKey, IndexKeyPrefix, LogKey,
    Serialize, ValueKey,
};

pub mod bitmap;
pub mod main;
pub mod read;
pub mod write;

impl<T: AsRef<[u8]>> Serialize for &IndexKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len() + 1)
            .write(SUBSPACE_INDEXES)
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
            .write(SUBSPACE_INDEXES)
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
                .write(SUBSPACE_VALUES)
                .write_leb128(self.account_id)
                .write(self.collection)
                .write_leb128(self.document_id)
                .write(self.field)
                .finalize()
        } else {
            KeySerializer::new(std::mem::size_of::<ValueKey>() + 2)
                .write(SUBSPACE_VALUES)
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
            .write(SUBSPACE_BITMAPS)
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
            .write(SUBSPACE_BLOBS)
            .write(hash)
            .write_leb128(self.account_id)
            .write(self.collection)
            .write_leb128(self.document_id)
            .finalize()
    }
}

impl Serialize for &AclKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<AclKey>() + 1)
            .write(SUBSPACE_ACLS)
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
            .write(SUBSPACE_LOGS)
            .write(self.account_id)
            .write(self.collection)
            .write(self.change_id)
            .finalize()
    }
}

impl From<FdbError> for Error {
    fn from(error: FdbError) -> Self {
        Self::InternalError(format!("FoundationDB error: {}", error.message()))
    }
}
