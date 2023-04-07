pub mod purge;
pub mod read;
pub mod write;

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use utils::{codec::base32_custom::Base32Writer, config::Config};

use crate::{BlobHash, Serialize};

pub enum BlobStore {
    Local {
        base_path: PathBuf,
        hash_levels: usize,
    },
    Remote(String),
}

impl BlobStore {
    pub async fn new(config: &Config) -> crate::Result<Self> {
        Ok(BlobStore::Local {
            base_path: config.value_require("blob.store.path")?.into(),
            hash_levels: config.property("blob.store.hash")?.unwrap_or(1),
        })
    }
}

impl Serialize for &BlobHash {
    fn serialize(self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

impl From<std::io::Error> for crate::Error {
    fn from(err: std::io::Error) -> Self {
        Self::InternalError(format!("IO error: {}", err))
    }
}

fn get_path(base_path: &Path, hash_levels: usize, blob_id: &BlobHash) -> crate::Result<PathBuf> {
    let mut path = base_path.to_path_buf();
    let hash = &blob_id.hash;
    for byte in hash.iter().take(hash_levels) {
        path.push(format!("{:x}", byte));
    }

    // Base32 encode the hash
    let mut writer = Base32Writer::with_capacity(hash.len());
    writer.write_all(hash).unwrap();
    path.push(&writer.finalize());

    Ok(path)
}
