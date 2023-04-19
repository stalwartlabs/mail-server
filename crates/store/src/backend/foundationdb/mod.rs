use foundationdb::FdbError;

use crate::Error;

pub mod bitmap;
pub mod main;
pub mod read;
pub mod write;

impl From<FdbError> for Error {
    fn from(error: FdbError) -> Self {
        Self::InternalError(format!("FoundationDB error: {}", error.message()))
    }
}
