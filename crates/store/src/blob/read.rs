use std::{io::SeekFrom, ops::Range};

use roaring::RoaringBitmap;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::{write::key::DeserializeBigEndian, BlobHash, BlobKey, Store, BLOB_HASH_LEN};

use super::{get_path, BlobStore};

impl Store {
    pub async fn get_blob(
        &self,
        id: &BlobHash,
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        match &self.blob {
            BlobStore::Local {
                base_path,
                hash_levels,
            } => {
                let blob_path = get_path(base_path, *hash_levels, id)?;
                let blob_size = match fs::metadata(&blob_path).await {
                    Ok(m) => m.len(),
                    Err(_) => return Ok(None),
                };
                let mut blob = File::open(&blob_path).await?;

                Ok(Some(if range.start != 0 || range.end != u32::MAX {
                    let from_offset = if range.start < blob_size as u32 {
                        range.start
                    } else {
                        0
                    };
                    let mut buf = vec![
                        0;
                        (std::cmp::min(range.end, blob_size as u32) - from_offset)
                            as usize
                    ];

                    if from_offset > 0 {
                        blob.seek(SeekFrom::Start(from_offset as u64)).await?;
                    }
                    blob.read_exact(&mut buf).await?;
                    buf
                } else {
                    let mut buf = Vec::with_capacity(blob_size as usize);
                    blob.read_to_end(&mut buf).await?;
                    buf
                }))
            }
            BlobStore::Remote(_) => todo!(),
        }
    }

    pub async fn has_blob_access(
        &self,
        blob_hash: &BlobHash,
        account_ids: Vec<u32>,
    ) -> crate::Result<bool> {
        // Check if the blob already exists
        let from_key = BlobKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            hash: blob_hash.hash,
        };
        let to_key = BlobKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            hash: blob_hash.hash,
        };

        self.iterate(false, from_key, to_key, true, false, move |acc, key, _| {
            let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
            if account_ids.contains(&account_id) {
                *acc = true;
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .await
    }

    pub async fn has_blob_access_doc(
        &self,
        blob_hash: &BlobHash,
        account_id: u32,
        collection: impl Into<u8>,
        document_ids: RoaringBitmap,
    ) -> crate::Result<bool> {
        // Check if the blob already exists
        let collection = collection.into();
        let from_key = BlobKey {
            account_id,
            collection,
            document_id: 0,
            hash: blob_hash.hash,
        };
        let to_key = BlobKey {
            account_id,
            collection,
            document_id: u32::MAX,
            hash: blob_hash.hash,
        };

        self.iterate(false, from_key, to_key, true, false, move |acc, key, _| {
            let document_id =
                key.deserialize_be_u32(BLOB_HASH_LEN + std::mem::size_of::<u32>() + 1)?;
            if document_ids.contains(document_id) {
                *acc = true;
                Ok(false)
            } else {
                Ok(true)
            }
        })
        .await
    }
}
