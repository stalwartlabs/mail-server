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

use std::{io::ErrorKind, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest::{Context, SHA512};

use super::{AcmeError, AcmeManager};

impl AcmeManager {
    pub(crate) async fn load_cert(&self) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists("cert", self.domains.as_slice())
            .await
            .map_err(AcmeError::CertCacheLoad)
    }

    pub(crate) async fn store_cert(&self, cert: &[u8]) -> Result<(), AcmeError> {
        self.write("cert", self.domains.as_slice(), cert)
            .await
            .map_err(AcmeError::CertCacheStore)
    }

    pub(crate) async fn load_account(&self) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists("key", self.contact.as_slice())
            .await
            .map_err(AcmeError::AccountCacheLoad)
    }

    pub(crate) async fn store_account(&self, account: &[u8]) -> Result<(), AcmeError> {
        self.write("key", self.contact.as_slice(), account)
            .await
            .map_err(AcmeError::AccountCacheStore)
    }

    async fn read_if_exists(
        &self,
        class: &str,
        items: &[String],
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        match tokio::fs::read(self.build_filename(class, items)).await {
            Ok(content) => Ok(Some(content)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }

    async fn write(
        &self,
        class: &str,
        items: &[String],
        contents: impl AsRef<[u8]>,
    ) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.cache_path).await?;
        tokio::fs::write(self.build_filename(class, items), contents.as_ref()).await
    }

    fn build_filename(&self, class: &str, items: &[String]) -> PathBuf {
        let mut ctx = Context::new(&SHA512);
        for el in items {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(self.directory_url.as_bytes());

        self.cache_path.join(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(ctx.finish()),
            class
        ))
    }
}
