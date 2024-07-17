/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::{self, Cursor, Read},
    path::PathBuf,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use store::BlobStore;

use crate::Core;

use super::WEBADMIN_KEY;

pub struct WebAdminManager {
    bundle_path: TempDir,
    routes: ArcSwap<AHashMap<String, Resource<PathBuf>>>,
}

#[derive(Default)]
pub struct Resource<T> {
    pub content_type: &'static str,
    pub contents: T,
}

impl WebAdminManager {
    pub fn new() -> Self {
        Self {
            bundle_path: TempDir::new(),
            routes: ArcSwap::from_pointee(Default::default()),
        }
    }

    pub async fn get(&self, path: &str) -> trc::Result<Resource<Vec<u8>>> {
        let routes = self.routes.load();
        if let Some(resource) = routes.get(path).or_else(|| routes.get("index.html")) {
            tokio::fs::read(&resource.contents)
                .await
                .map(|contents| Resource {
                    content_type: resource.content_type,
                    contents,
                })
                .map_err(|err| {
                    trc::ResourceCause::Error
                        .reason(err)
                        .ctx(trc::Key::Path, path.to_string())
                        .caused_by(trc::location!())
                })
        } else {
            Ok(Resource::default())
        }
    }

    pub async fn unpack(&self, blob_store: &BlobStore) -> trc::Result<()> {
        // Delete any existing bundles
        self.bundle_path.clean().await.map_err(unpack_error)?;

        // Obtain webadmin bundle
        let bundle = blob_store
            .get_blob(WEBADMIN_KEY, 0..usize::MAX)
            .await?
            .ok_or_else(|| {
                trc::ResourceCause::NotFound
                    .caused_by(trc::location!())
                    .details("Webadmin bundle not found")
            })?;

        // Uncompress
        let mut bundle = zip::ZipArchive::new(Cursor::new(bundle)).map_err(|err| {
            trc::ResourceCause::Error
                .caused_by(trc::location!())
                .reason(err)
                .details("Failed to decompress webadmin bundle")
        })?;
        let mut routes = AHashMap::new();
        for i in 0..bundle.len() {
            let (file_name, contents) = {
                let mut file = bundle.by_index(i).map_err(|err| {
                    trc::ResourceCause::Error
                        .caused_by(trc::location!())
                        .reason(err)
                        .details("Failed to read file from webadmin bundle")
                })?;
                if file.is_dir() {
                    continue;
                }

                let mut contents = Vec::new();
                file.read_to_end(&mut contents).map_err(unpack_error)?;
                (file.name().to_string(), contents)
            };
            let path = self.bundle_path.path.join(format!("{i:02}"));
            tokio::fs::write(&path, contents)
                .await
                .map_err(unpack_error)?;

            let resource = Resource {
                content_type: match file_name
                    .rsplit_once('.')
                    .map(|(_, ext)| ext)
                    .unwrap_or_default()
                {
                    "html" => "text/html",
                    "css" => "text/css",
                    "wasm" => "application/wasm",
                    "js" => "application/javascript",
                    "json" => "application/json",
                    "png" => "image/png",
                    "svg" => "image/svg+xml",
                    "ico" => "image/x-icon",
                    _ => "application/octet-stream",
                },
                contents: path,
            };

            routes.insert(file_name, resource);
        }

        // Update routes
        self.routes.store(routes.into());

        tracing::debug!(
            path = self.bundle_path.path.to_string_lossy().as_ref(),
            "WebAdmin successfully unpacked"
        );

        Ok(())
    }

    pub async fn update_and_unpack(&self, core: &Core) -> trc::Result<()> {
        let bytes = core
            .storage
            .config
            .fetch_resource("webadmin")
            .await
            .map_err(|err| {
                trc::Cause::Fetch
                    .caused_by(trc::location!())
                    .reason(err)
                    .details("Failed to download webadmin")
            })?;
        core.storage.blob.put_blob(WEBADMIN_KEY, &bytes).await?;
        self.unpack(&core.storage.blob).await
    }
}

impl Resource<Vec<u8>> {
    pub fn is_empty(&self) -> bool {
        self.content_type.is_empty() && self.contents.is_empty()
    }
}

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new() -> TempDir {
        TempDir {
            path: std::env::temp_dir().join(std::str::from_utf8(WEBADMIN_KEY).unwrap()),
        }
    }

    pub async fn clean(&self) -> io::Result<()> {
        if tokio::fs::metadata(&self.path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&self.path).await;
        }
        tokio::fs::create_dir(&self.path).await
    }
}

fn unpack_error(err: std::io::Error) -> trc::Error {
    trc::ResourceCause::Error
        .reason(err)
        .details("Failed to unpack webadmin bundle")
}

impl Default for WebAdminManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
