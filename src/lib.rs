use rocksdb::{MultiThreaded, OptimisticTransactionDB};

pub mod backend;
pub mod fts;
pub mod query;
pub mod write;

pub struct Store {
    db: OptimisticTransactionDB<MultiThreaded>,
}

pub trait Deserialize: Sized + Sync + Send {
    fn deserialize(bytes: &[u8]) -> Option<Self>;
}

pub trait Serialize {
    fn serialize(self) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BitmapKey<'x> {
    pub account_id: u32,
    pub collection: u8,
    pub family: u8,
    pub field: u8,
    pub key: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexKey<'x> {
    pub account_id: u32,
    pub collection: u8,
    pub field: u8,
    pub key: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueKey {
    pub account_id: u32,
    pub collection: u8,
    pub document_id: u32,
    pub field: u8,
}

pub type Result<T> = std::result::Result<T, Error>;

pub enum Error {
    NotFound,
    InternalError(String),
}

pub const BM_DOCUMENT_IDS: u8 = 0;
pub const BM_TERM: u8 = 0x10;
pub const BM_TAG: u8 = 0x20;

pub const TERM_EXACT: u8 = 0x00;
pub const TERM_STEMMED: u8 = 0x01;
pub const TERM_STRING: u8 = 0x02;
pub const TERM_HASH: u8 = 0x04;

pub const TAG_ID: u8 = 0x00;
pub const TAG_TEXT: u8 = 0x01;
pub const TAG_STATIC: u8 = 0x02;

#[cfg(test)]
mod tests {
    use rand::Rng;
    use roaring::RoaringBitmap;

    use super::*;

    #[test]
    fn it_works() {
        let mut rb1 = RoaringBitmap::new();
        let mut rb2 = RoaringBitmap::new();
        let total = rand::thread_rng().gen_range(0..100000);
        println!("total: {}", total);

        for num in 0..total {
            rb1.insert(rand::thread_rng().gen_range(0..u32::MAX));
            rb2.insert(num);
        }

        println!("sparse: {}", rb1.serialized_size());
        println!("compact: {}", rb2.serialized_size());
        println!(
            "ratio: {}",
            rb1.serialized_size() as f64 / rb2.serialized_size() as f64
        );
    }
}
