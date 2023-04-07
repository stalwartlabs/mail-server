use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

use crate::{write::BatchBuilder, BlobHash, BlobKey, Store, BLOB_HASH_LEN};

use super::{get_path, BlobStore};

impl Store {
    pub async fn write_blob(&self, account_id: u32, data: &[u8]) -> crate::Result<BlobHash> {
        let id = BlobHash::from(data);

        // Check if the blob already exists
        let from_key = BlobKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            hash: [0; BLOB_HASH_LEN],
        };
        let to_key = BlobKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            hash: id.hash,
        };

        let found = self
            .iterate(false, from_key, to_key, true, false, |acc, _, _| {
                *acc = true;
                Ok(false)
            })
            .await?;

        if !found {
            // Write the blob
            self.blob.put(&id, data).await?;

            // Write a temporary link to the blob
            self.write(
                BatchBuilder::new()
                    .with_account_id(account_id)
                    .with_collection(u8::MAX)
                    .update_document(u32::MAX)
                    .blob(&id, 0)
                    .build_batch(),
            )
            .await?;
        }

        Ok(id)
    }
}

impl BlobStore {
    pub async fn put(&self, id: &BlobHash, data: &[u8]) -> crate::Result<bool> {
        match self {
            BlobStore::Local {
                base_path,
                hash_levels,
            } => {
                let blob_path = get_path(base_path, *hash_levels, id)?;

                if blob_path.exists() {
                    let metadata = fs::metadata(&blob_path).await?;
                    if metadata.len() as usize == data.len() {
                        return Ok(false);
                    }
                }

                fs::create_dir_all(blob_path.parent().unwrap()).await?;
                let mut blob_file = File::create(&blob_path).await?;
                blob_file.write_all(data).await?;
                blob_file.flush().await?;

                Ok(true)
            }
            BlobStore::Remote(_) => todo!(),
        }
    }

    pub async fn delete(&self, id: &BlobHash) -> crate::Result<bool> {
        match self {
            BlobStore::Local {
                base_path,
                hash_levels,
            } => {
                let blob_path = get_path(base_path, *hash_levels, id)?;

                if blob_path.exists() {
                    fs::remove_file(&blob_path).await?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            BlobStore::Remote(_) => todo!(),
        }
    }
}

impl From<&[u8]> for BlobHash {
    fn from(data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        Self {
            hash: hasher.finalize().into(),
        }
    }
}
