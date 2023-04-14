use foundationdb::FdbError;

use crate::{
    write::key::KeySerializer, AclKey, BitmapKey, BlobKey, Error, IndexKey, IndexKeyPrefix, LogKey,
    Serialize, ValueKey,
};

pub mod bitmap;
pub mod main;
pub mod read;
pub mod write;

impl From<FdbError> for Error {
    fn from(error: FdbError) -> Self {
        Self::InternalError(format!("FoundationDB error: {}", error.message()))
    }
}
