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

use std::ops::Range;

use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

use crate::{BlobKind, Store};

use super::{get_local_path, get_local_root_path, get_s3_path, get_s3_root_path, BlobStore};

impl Store {
    pub async fn put_blob(&self, kind: &BlobKind, data: &[u8]) -> crate::Result<()> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_local_path(base_path, kind);

                fs::create_dir_all(blob_path.parent().unwrap()).await?;
                let mut blob_file = File::create(&blob_path).await?;
                blob_file.write_all(data).await?;
                blob_file.flush().await?;

                Ok(())
            }
            BlobStore::Remote(bucket) => {
                let path = get_s3_path(kind);
                match bucket.put_object(path, data).await {
                    Ok(response) if (200..300).contains(&response.status_code()) => Ok(()),
                    Ok(response) => Err(crate::Error::InternalError(format!(
                        "S3 error code {}: {}",
                        response.status_code(),
                        String::from_utf8_lossy(response.as_slice())
                    ))),
                    Err(e) => Err(e.into()),
                }
            }
        }
    }

    pub async fn copy_blob(
        &self,
        src: &BlobKind,
        dest: &BlobKind,
        range: Option<Range<u32>>,
    ) -> crate::Result<bool> {
        if let Some(range) = range {
            if let Some(bytes) = self.get_blob(src, range).await? {
                self.put_blob(dest, &bytes).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            match &self.blob {
                BlobStore::Local(base_path) => {
                    let dest_path = get_local_path(base_path, dest);
                    let src_path = get_local_path(base_path, src);

                    if fs::metadata(&src_path).await.is_ok() {
                        fs::create_dir_all(dest_path.parent().unwrap()).await?;
                        fs::copy(src_path, dest_path).await?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
                BlobStore::Remote(bucket) => {
                    let src_path = get_s3_path(src);
                    let dest_path = get_s3_path(dest);

                    bucket
                        .copy_object_internal(src_path, dest_path)
                        .await
                        .map(|code| (200..300).contains(&code))
                        .map_err(|e| e.into())
                }
            }
        }
    }

    pub async fn delete_blob(&self, kind: &BlobKind) -> crate::Result<bool> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_local_path(base_path, kind);

                if blob_path.exists() {
                    fs::remove_file(&blob_path).await?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            BlobStore::Remote(bucket) => {
                let path = get_s3_path(kind);
                bucket
                    .delete_object(path)
                    .await
                    .map(|response| (200..300).contains(&response.status_code()))
                    .map_err(|e| e.into())
            }
        }
    }

    pub async fn bulk_delete_blob(&self, kind: &BlobKind) -> crate::Result<()> {
        match &self.blob {
            BlobStore::Local(base_path) => fs::remove_dir_all(get_local_root_path(base_path, kind))
                .await
                .map_err(Into::into),
            BlobStore::Remote(bucket) => {
                let prefix = get_s3_root_path(kind);
                let prefix_base = prefix.strip_prefix('/').unwrap();
                let mut is_truncated = true;
                while is_truncated {
                    for item in bucket.list(prefix.clone(), None).await? {
                        is_truncated = item.is_truncated && !item.contents.is_empty();
                        for object in item.contents {
                            if object.key.starts_with(&prefix)
                                || object.key.starts_with(prefix_base)
                            {
                                let result = bucket.delete_object(object.key).await?;
                                if !(200..300).contains(&result.status_code()) {
                                    return Err(crate::Error::InternalError(format!(
                                        "Failed to delete bucket item, code {}: {}",
                                        result.status_code(),
                                        String::from_utf8_lossy(result.as_slice())
                                    )));
                                }
                            } else {
                                tracing::debug!(
                                    "Unexpected S3 object while deleting: {}",
                                    item.name
                                );
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    }
}
