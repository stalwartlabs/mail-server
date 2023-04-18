use std::{io::SeekFrom, ops::Range};

use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::{BlobKind, Store};

use super::{get_path, BlobStore};

impl Store {
    pub async fn get_blob(
        &self,
        kind: &BlobKind,
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_path(base_path, kind)?;
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
}
