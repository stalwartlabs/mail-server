/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use std::{
    io::{self, Cursor, Read},
    path::PathBuf,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use store::BlobStore;

use super::{download_resource, WEBADMIN_KEY, WEBADMIN_URL};

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

    pub async fn get(&self, path: &str) -> io::Result<Resource<Vec<u8>>> {
        let routes = self.routes.load();
        if let Some(resource) = routes.get(path).or_else(|| routes.get("index.html")) {
            tokio::fs::read(&resource.contents)
                .await
                .map(|contents| Resource {
                    content_type: resource.content_type,
                    contents,
                })
        } else {
            Ok(Resource::default())
        }
    }

    pub async fn unpack(&self, blob_store: &BlobStore) -> store::Result<()> {
        // Delete any existing bundles
        self.bundle_path.clean().await?;

        // Obtain webadmin bundle
        let bundle = blob_store
            .get_blob(WEBADMIN_KEY, 0..usize::MAX)
            .await?
            .ok_or_else(|| store::Error::InternalError("WebAdmin bundle not found".to_string()))?;

        // Uncompress
        let mut bundle = zip::ZipArchive::new(Cursor::new(bundle))
            .map_err(|err| store::Error::InternalError(format!("Unzip error: {err}")))?;
        let mut routes = AHashMap::new();
        for i in 0..bundle.len() {
            let (file_name, contents) = {
                let mut file = bundle
                    .by_index(i)
                    .map_err(|err| store::Error::InternalError(format!("Unzip error: {err}")))?;
                if file.is_dir() {
                    continue;
                }

                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                (file.name().to_string(), contents)
            };
            let path = self.bundle_path.path.join(format!("{i:02}"));
            tokio::fs::write(&path, contents).await?;

            let resource = Resource {
                content_type: match file_name
                    .rsplit_once('.')
                    .map(|(_, ext)| ext)
                    .unwrap_or_default()
                {
                    "html" => "text/html",
                    "css" => "text/css",
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

        Ok(())
    }

    pub async fn update_and_unpack(&self, blob_store: &BlobStore) -> store::Result<()> {
        let bytes = download_resource(WEBADMIN_URL).await.map_err(|err| {
            store::Error::InternalError(format!("Failed to download webadmin: {err}"))
        })?;
        blob_store.put_blob(WEBADMIN_KEY, &bytes).await?;
        self.unpack(blob_store).await
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
