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

use crate::{write::now, BlobKind, Store};

use super::{get_local_path, get_s3_path, BlobStore};

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

    pub async fn delete_account_blobs(&self, account_id: u32) -> crate::Result<()> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                for path in [
                    &base_path.path_email,
                    &base_path.path_other,
                    &base_path.path_temporary,
                ] {
                    let mut path = path.to_path_buf();
                    path.push(format!("{:x}", account_id));
                    if fs::metadata(&path).await.is_ok() {
                        fs::remove_dir_all(path).await?;
                    }
                }

                Ok(())
            }
            BlobStore::Remote(bucket) => {
                for prefix in [
                    format!("/{:x}/", account_id),
                    format!("/tmp/{:x}/", account_id),
                ] {
                    let prefix_base = prefix.strip_prefix('/').unwrap();
                    for object in bucket
                        .list(prefix.clone(), None)
                        .await?
                        .into_iter()
                        .flat_map(|result| result.contents)
                    {
                        if object.key.starts_with(&prefix) || object.key.starts_with(prefix_base) {
                            let result = bucket.delete_object(object.key).await?;
                            if !(200..300).contains(&result.status_code()) {
                                return Err(crate::Error::InternalError(format!(
                                    "Failed to delete bucket item, code {}: {}",
                                    result.status_code(),
                                    String::from_utf8_lossy(result.as_slice())
                                )));
                            }
                        } else {
                            tracing::debug!("Unexpected S3 object while deleting: {}", object.key);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn purge_tmp_blobs(&self, ttl: u64) -> crate::Result<()> {
        let now = now();
        match &self.blob {
            BlobStore::Local(base_path) => {
                if fs::metadata(&base_path.path_temporary).await.is_ok() {
                    let mut dir = fs::read_dir(&base_path.path_temporary).await?;
                    while let Some(item) = dir.next_entry().await? {
                        if item.metadata().await?.is_dir() {
                            let mut dir = fs::read_dir(item.path()).await?;
                            while let Some(item) = dir.next_entry().await? {
                                if item.metadata().await?.is_file() {
                                    if let Some(timestamp) =
                                        item.file_name().to_str().and_then(parse_timestamp)
                                    {
                                        if now.saturating_sub(timestamp) > ttl {
                                            fs::remove_file(item.path()).await?;
                                        }
                                    } else {
                                        tracing::debug!(
                                            "Found invalid temporary filename while purging: {}",
                                            item.file_name().to_string_lossy()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(())
            }
            BlobStore::Remote(bucket) => {
                for object in bucket
                    .list("/tmp/".to_string(), None)
                    .await?
                    .into_iter()
                    .flat_map(|result| result.contents)
                {
                    if object.key.starts_with("/tmp/") || object.key.starts_with("tmp/") {
                        if let Some(timestamp) = object
                            .key
                            .rsplit_once('/')
                            .and_then(|(_, name)| parse_timestamp(name))
                        {
                            if now.saturating_sub(timestamp) > ttl {
                                let result = bucket.delete_object(object.key).await?;
                                if !(200..300).contains(&result.status_code()) {
                                    return Err(crate::Error::InternalError(format!(
                                        "Failed to delete bucket item, code {}: {}",
                                        result.status_code(),
                                        String::from_utf8_lossy(result.as_slice())
                                    )));
                                }
                            }
                        } else {
                            tracing::debug!(
                                "Found invalid temporary filename while purging: {}",
                                object.key
                            );
                        }
                    } else {
                        tracing::debug!("Unexpected S3 object while purging: {}", object.key);
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn get_tmp_blob_usage(
        &self,
        account_id: u32,
        ttl: u64,
    ) -> crate::Result<(usize, usize)> {
        let now = now();
        let mut total_bytes = 0;
        let mut total_files = 0;

        match &self.blob {
            BlobStore::Local(base_path) => {
                let mut path = base_path.path_temporary.to_path_buf();
                path.push(format!("{:x}", account_id));

                if fs::metadata(&path).await.is_ok() {
                    let mut dir = fs::read_dir(path).await?;
                    while let Some(item) = dir.next_entry().await? {
                        match item.metadata().await {
                            Ok(metadata) if metadata.is_file() => {
                                if let Some(timestamp) =
                                    item.file_name().to_str().and_then(parse_timestamp)
                                {
                                    if now.saturating_sub(timestamp) > ttl {
                                        fs::remove_file(item.path()).await?;
                                    } else {
                                        total_bytes += metadata.len() as usize;
                                        total_files += 1;
                                    }
                                } else {
                                    tracing::debug!(
                                        "Found invalid temporary filename while purging: {}",
                                        item.file_name().to_string_lossy()
                                    );
                                }
                            }
                            _ => (),
                        }
                    }
                }
            }
            BlobStore::Remote(bucket) => {
                let prefix = format!("/tmp/{:x}/", account_id);
                let prefix_base = prefix.strip_prefix('/').unwrap();
                for object in bucket
                    .list(prefix.clone(), None)
                    .await?
                    .into_iter()
                    .flat_map(|result| result.contents)
                {
                    if object.key.starts_with(prefix_base) || object.key.starts_with(&prefix) {
                        if let Some(timestamp) = object
                            .key
                            .rsplit_once('/')
                            .and_then(|(_, name)| parse_timestamp(name))
                        {
                            if now.saturating_sub(timestamp) > ttl {
                                let result = bucket.delete_object(object.key).await?;
                                if !(200..300).contains(&result.status_code()) {
                                    return Err(crate::Error::InternalError(format!(
                                        "Failed to delete bucket item, code {}: {}",
                                        result.status_code(),
                                        String::from_utf8_lossy(result.as_slice())
                                    )));
                                }
                            } else {
                                total_bytes += object.size as usize;
                                total_files += 1;
                            }
                        } else {
                            tracing::debug!(
                                "Found invalid temporary filename while purging: {}",
                                object.key
                            );
                        }
                    } else {
                        tracing::debug!("Unexpected S3 object while purging: {}", object.key);
                    }
                }
            }
        }

        Ok((total_files, total_bytes))
    }
}

fn parse_timestamp(name: &str) -> Option<u64> {
    name.split_once('_')
        .and_then(|(timestamp, _)| u64::from_str_radix(timestamp, 16).ok())
}
