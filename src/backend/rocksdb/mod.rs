use crate::{write::key::KeySerializer, BitmapKey, IndexKey, Serialize, ValueKey};

pub mod bitmap;
pub mod main;
pub mod read;

pub const CF_BITMAPS: &str = "b";
pub const CF_VALUES: &str = "v";
pub const CF_LOGS: &str = "l";
pub const CF_BLOBS: &str = "o";
pub const CF_INDEXES: &str = "i";

pub const COLLECTION_PREFIX_LEN: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();
pub const FIELD_PREFIX_LEN: usize = COLLECTION_PREFIX_LEN + std::mem::size_of::<u8>();
pub const ACCOUNT_KEY_LEN: usize =
    std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + std::mem::size_of::<u32>();

impl Serialize for IndexKey<'_> {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<IndexKey>() + self.key.len())
            .write(self.account_id)
            .write(self.collection)
            .write(self.field)
            .write(self.key)
            .finalize()
    }
}

impl Serialize for ValueKey {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<ValueKey>())
            .write_leb128(self.account_id)
            .write(self.collection)
            .write_leb128(self.document_id)
            .write(self.field)
            .finalize()
    }
}

impl Serialize for BitmapKey<'_> {
    fn serialize(self) -> Vec<u8> {
        KeySerializer::new(std::mem::size_of::<BitmapKey>() + self.key.len())
            .write(self.key)
            .write(self.field)
            .write(self.collection)
            .write(self.family)
            .write_leb128(self.account_id)
            .finalize()
    }
}
