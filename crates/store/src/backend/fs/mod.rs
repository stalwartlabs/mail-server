/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{io::SeekFrom, ops::Range, path::PathBuf};

use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use utils::{
    codec::base32_custom::Base32Writer,
    config::{utils::AsKey, Config},
};

pub struct FsStore {
    path: PathBuf,
    hash_levels: usize,
}

impl FsStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let path = PathBuf::from(config.value_require((&prefix, "path"))?);
        if !path.exists() {
            fs::create_dir_all(&path)
                .await
                .map_err(|e| {
                    config.new_build_error(
                        (&prefix, "path"),
                        format!("Failed to create directory: {e}"),
                    )
                })
                .ok()?;
        }

        Some(FsStore {
            path,
            hash_levels: std::cmp::min(
                config
                    .property_or_default((&prefix, "depth"), "2")
                    .unwrap_or(2),
                5,
            ),
        })
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let blob_path = self.build_path(key);
        let blob_size = match fs::metadata(&blob_path).await {
            Ok(m) => m.len() as usize,
            Err(_) => return Ok(None),
        };
        let mut blob = File::open(&blob_path).await?;

        Ok(Some(if range.start != 0 || range.end != usize::MAX {
            let from_offset = if range.start < blob_size {
                range.start
            } else {
                0
            };
            let mut buf = vec![0; (std::cmp::min(range.end, blob_size) - from_offset) as usize];

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

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        let blob_path = self.build_path(key);

        if fs::metadata(&blob_path)
            .await
            .map_or(true, |m| m.len() as usize != data.len())
        {
            fs::create_dir_all(blob_path.parent().unwrap()).await?;
            let mut blob_file = File::create(&blob_path).await?;
            blob_file.write_all(data).await?;
            blob_file.flush().await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        let blob_path = self.build_path(key);
        if fs::metadata(&blob_path).await.is_ok() {
            fs::remove_file(&blob_path).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn build_path(&self, key: &[u8]) -> PathBuf {
        let mut path = self.path.clone();

        for byte in key.iter().take(self.hash_levels) {
            path.push(format!("{:x}", byte));
        }
        path.push(Base32Writer::from_bytes(key).finalize());
        path
    }
}
