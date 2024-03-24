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

use std::io::ErrorKind;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::digest::{Context, SHA512};
use utils::config::ConfigKey;

use super::{AcmeError, AcmeManager};

impl AcmeManager {
    pub(crate) async fn load_cert(&self) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists("private-key", self.domains.as_slice())
            .await
            .map_err(AcmeError::CertCacheLoad)
    }

    pub(crate) async fn store_cert(&self, cert: &[u8]) -> Result<(), AcmeError> {
        self.write("private-key", self.domains.as_slice(), cert)
            .await
            .map_err(AcmeError::CertCacheStore)
    }

    pub(crate) async fn load_account(&self) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists("cert", self.contact.as_slice())
            .await
            .map_err(AcmeError::AccountCacheLoad)
    }

    pub(crate) async fn store_account(&self, account: &[u8]) -> Result<(), AcmeError> {
        self.write("cert", self.contact.as_slice(), account)
            .await
            .map_err(AcmeError::AccountCacheStore)
    }

    async fn read_if_exists(
        &self,
        class: &str,
        items: &[String],
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self
            .store
            .load()
            .config_get(self.build_key(class, items))
            .await
        {
            Ok(Some(content)) => match URL_SAFE_NO_PAD.decode(content.as_bytes()) {
                Ok(contents) => Ok(Some(contents)),
                Err(err) => Err(std::io::Error::new(ErrorKind::Other, err)),
            },
            Ok(None) => Ok(None),
            Err(err) => Err(std::io::Error::new(ErrorKind::Other, err)),
        }
    }

    async fn write(
        &self,
        class: &str,
        items: &[String],
        contents: impl AsRef<[u8]>,
    ) -> Result<(), std::io::Error> {
        self.store
            .load()
            .config_set([ConfigKey {
                key: self.build_key(class, items),
                value: URL_SAFE_NO_PAD.encode(contents.as_ref()),
            }])
            .await
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }

    fn build_key(&self, class: &str, items: &[String]) -> String {
        let mut ctx = Context::new(&SHA512);
        for el in items {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(self.directory_url.as_bytes());

        format!(
            "certificate.acme-{}-{}.{}",
            self.id,
            URL_SAFE_NO_PAD.encode(ctx.finish()),
            class
        )
    }
}
