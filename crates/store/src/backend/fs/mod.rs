/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
    pub async fn open(config: &Config, prefix: impl AsKey) -> crate::Result<Self> {
        let prefix = prefix.as_key();
        let path = config.property_require::<PathBuf>((&prefix, "path"))?;
        if path.exists() {
            Ok(FsStore {
                path,
                hash_levels: std::cmp::min(config.property_or_static((&prefix, "depth"), "2")?, 5),
            })
        } else {
            Err(crate::Error::InternalError(format!(
                "Blob store path {:?} does not exist",
                path
            )))
        }
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        let blob_path = self.build_path(key);
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
            let mut buf =
                vec![0; (std::cmp::min(range.end, blob_size as u32) - from_offset) as usize];

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
