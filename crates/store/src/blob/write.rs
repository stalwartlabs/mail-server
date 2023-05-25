use std::ops::Range;

use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

use crate::{BlobKind, Store};

use super::{get_path, get_root_path, BlobStore};

impl Store {
    pub async fn put_blob(&self, kind: &BlobKind, data: &[u8]) -> crate::Result<bool> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_path(base_path, kind)?;

                fs::create_dir_all(blob_path.parent().unwrap()).await?;
                let mut blob_file = File::create(&blob_path).await?;
                blob_file.write_all(data).await?;
                blob_file.flush().await?;

                Ok(true)
            }
            BlobStore::Remote(_) => todo!(),
        }
    }

    pub async fn copy_blob(
        &self,
        src: &BlobKind,
        dest: &BlobKind,
        range: Option<Range<u32>>,
    ) -> crate::Result<bool> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let dest_path = get_path(base_path, dest)?;

                if let Some(range) = range {
                    if let Some(bytes) = self.get_blob(src, range).await? {
                        fs::create_dir_all(dest_path.parent().unwrap()).await?;
                        fs::write(dest_path, bytes).await?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    let src_path = get_path(base_path, src)?;
                    if fs::metadata(&src_path).await.is_ok() {
                        fs::create_dir_all(dest_path.parent().unwrap()).await?;
                        fs::copy(src_path, dest_path).await?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
            BlobStore::Remote(_) => todo!(),
        }
    }

    pub async fn delete_blob(&self, kind: &BlobKind) -> crate::Result<bool> {
        match &self.blob {
            BlobStore::Local(base_path) => {
                let blob_path = get_path(base_path, kind)?;

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

    pub async fn bulk_delete_blob(&self, kind: &BlobKind) -> crate::Result<()> {
        match &self.blob {
            BlobStore::Local(base_path) => fs::remove_dir_all(get_root_path(base_path, kind)?)
                .await
                .map_err(Into::into),
            BlobStore::Remote(_) => todo!(),
        }
    }
}
