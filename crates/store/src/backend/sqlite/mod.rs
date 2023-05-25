pub mod id_assign;
pub mod main;
pub mod pool;
pub mod purge;
pub mod read;
pub mod write;

const WORD_SIZE_BITS: u32 = (WORD_SIZE * 8) as u32;
const WORD_SIZE: usize = std::mem::size_of::<u64>();
const WORDS_PER_BLOCK: u32 = 16;
pub const BITS_PER_BLOCK: u32 = WORD_SIZE_BITS * WORDS_PER_BLOCK;
const BITS_MASK: u32 = BITS_PER_BLOCK - 1;

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
