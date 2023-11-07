/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::{io::SeekFrom, ops::Range};

use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::{backend::sqlite::SqliteStore, BlobKind};

use super::{get_local_path, get_s3_path, BlobStore};

impl SqliteStore {
    pub async fn get_blob(
        &self,
        kind: &BlobKind,
        range: Range<u32>,
    ) -> crate::Result<Option<Vec<u8>>> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_local_path(base_path, kind);
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
            BlobStore::Remote(bucket) => {
                let path = get_s3_path(kind);
                let response = if range.start != 0 || range.end != u32::MAX {
                    bucket
                        .get_object_range(
                            path,
                            range.start as u64,
                            Some(range.end.saturating_sub(1) as u64),
                        )
                        .await
                } else {
                    bucket.get_object(path).await
                };
                match response {
                    Ok(response) if (200..300).contains(&response.status_code()) => {
                        Ok(Some(response.to_vec()))
                    }
                    Ok(response) if response.status_code() == 404 => Ok(None),
                    Ok(response) => Err(crate::Error::InternalError(format!(
                        "S3 error code {}: {}",
                        response.status_code(),
                        String::from_utf8_lossy(response.as_slice())
                    ))),
                    Err(err) => Err(err.into()),
                }
            }
        }
    }
}
