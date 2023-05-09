use std::convert::TryInto;
use utils::codec::leb128::Leb128_;

use crate::{
    AclKey, BitmapKey, Deserialize, Error, IndexKey, IndexKeyPrefix, Key, LogKey, Serialize,
    ValueKey, SUBSPACE_BITMAPS, SUBSPACE_INDEXES, SUBSPACE_LOGS, SUBSPACE_VALUES,
};

pub struct KeySerializer {
    buf: Vec<u8>,
}

pub trait KeySerialize {
    fn serialize(&self, buf: &mut Vec<u8>);
}

pub trait DeserializeBigEndian {
    fn deserialize_be_u32(&self, index: usize) -> crate::Result<u32>;
    fn deserialize_be_u64(&self, index: usize) -> crate::Result<u64>;
}

impl KeySerializer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn write<T: KeySerialize>(mut self, value: T) -> Self {
        value.serialize(&mut self.buf);
        self
    }

    pub fn write_leb128<T: Leb128_>(mut self, value: T) -> Self {
        T::to_leb128_bytes(value, &mut self.buf);
        self
    }

    pub fn finalize(self) -> Vec<u8> {
        self.buf
    }
}

impl KeySerialize for u8 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }
}

impl KeySerialize for &str {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &String {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl KeySerialize for &[u8] {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self);
    }
}

impl KeySerialize for u32 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u16 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl KeySerialize for u64 {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
    }
}

impl DeserializeBigEndian for &[u8] {
    fn deserialize_be_u32(&self, index: usize) -> crate::Result<u32> {
        self.get(index..index + std::mem::size_of::<u32>())
            .ok_or_else(|| {
                crate::Error::InternalError(
                    "Index out of range while deserializing u32.".to_string(),
                )
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    crate::Error::InternalError(
                        "Index out of range while deserializing u32.".to_string(),
                    )
                })
            })
            .map(u32::from_be_bytes)
    }

    fn deserialize_be_u64(&self, index: usize) -> crate::Result<u64> {
        self.get(index..index + std::mem::size_of::<u64>())
            .ok_or_else(|| {
                crate::Error::InternalError(
                    "Index out of range while deserializing u64.".to_string(),
                )
            })
            .and_then(|bytes| {
                bytes.try_into().map_err(|_| {
                    crate::Error::InternalError(
                        "Index out of range while deserializing u64.".to_string(),
                    )
                })
            })
            .map(u64::from_be_bytes)
    }
}

impl ValueKey {
    pub fn new(
        account_id: u32,
        collection: impl Into<u8>,
        document_id: u32,
        field: impl Into<u8>,
    ) -> Self {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            family: 0,
            field: field.into(),
        }
    }

    pub fn term_index(account_id: u32, collection: impl Into<u8>, document_id: u32) -> Self {
        ValueKey {
            account_id,
            collection: collection.into(),
            document_id,
            family: u8::MAX,
            field: u8::MAX,
        }
    }

    pub fn with_document_id(self, document_id: u32) -> Self {
        Self {
            document_id,
            ..self
        }
    }
}

impl<T: AsRef<[u8]>> Serialize for &IndexKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<IndexKey<T>>() + key.len())
            }
        }
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
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>() + 1)
                    .write(crate::SUBSPACE_INDEXES)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<IndexKeyPrefix>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.field)
        .finalize()
    }
}

impl Serialize for &ValueKey {
    fn serialize(self) -> Vec<u8> {
        let ks = {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<ValueKey>() + 2)
                    .write(crate::SUBSPACE_VALUES)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<ValueKey>() + 1)
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write_leb128(self.document_id);

        if self.family == 0 {
            ks.write(self.field).finalize()
        } else {
            ks.write(u8::MAX)
                .write(self.family)
                .write(self.field)
                .finalize()
        }
    }
}

impl<T: AsRef<[u8]>> Serialize for &BitmapKey<T> {
    fn serialize(self) -> Vec<u8> {
        let key = self.key.as_ref();
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<BitmapKey<T>>() + key.len() + 1)
                    .write(crate::SUBSPACE_BITMAPS)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<BitmapKey<T>>() + key.len())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.family)
        .write(self.field)
        .write(key)
        .write(self.block_num)
        .finalize()
    }
}

impl Serialize for &AclKey {
    fn serialize(self) -> Vec<u8> {
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<AclKey>() + 1).write(crate::SUBSPACE_ACLS)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<AclKey>())
            }
        }
        .write(self.grant_account_id)
        .write(u8::MAX)
        .write(self.to_account_id)
        .write(self.to_collection)
        .write(self.to_document_id)
        .finalize()
    }
}

impl Deserialize for AclKey {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Ok(AclKey {
            grant_account_id: bytes.deserialize_be_u32(0)?,
            to_account_id: bytes.deserialize_be_u32(std::mem::size_of::<u32>() + 1)?,
            to_collection: *bytes
                .get((std::mem::size_of::<u32>() * 2) + 1)
                .ok_or_else(|| Error::InternalError(format!("Corrupted acl key {bytes:?}")))?,
            to_document_id: bytes.deserialize_be_u32((std::mem::size_of::<u32>() * 2) + 2)?,
        })
    }
}

impl Serialize for &LogKey {
    fn serialize(self) -> Vec<u8> {
        {
            #[cfg(feature = "key_subspace")]
            {
                KeySerializer::new(std::mem::size_of::<LogKey>() + 1).write(crate::SUBSPACE_LOGS)
            }
            #[cfg(not(feature = "key_subspace"))]
            {
                KeySerializer::new(std::mem::size_of::<LogKey>())
            }
        }
        .write(self.account_id)
        .write(self.collection)
        .write(self.change_id)
        .finalize()
    }
}

impl Serialize for LogKey {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Key for LogKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_LOGS
    }
}

impl Key for ValueKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_VALUES
    }
}

impl Key for AclKey {
    fn subspace(&self) -> u8 {
        SUBSPACE_VALUES
    }
}

impl<T: AsRef<[u8]> + Sync + Send + 'static> Key for IndexKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_INDEXES
    }
}

impl<T: AsRef<[u8]> + Sync + Send + 'static> Key for BitmapKey<T> {
    fn subspace(&self) -> u8 {
        SUBSPACE_BITMAPS
    }
}

impl Serialize for ValueKey {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl Serialize for AclKey {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl<T: AsRef<[u8]>> Serialize for IndexKey<T> {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}

impl<T: AsRef<[u8]>> Serialize for BitmapKey<T> {
    fn serialize(self) -> Vec<u8> {
        (&self).serialize()
    }
}
