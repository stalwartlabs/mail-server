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
use utils::config::ConfigKey;

use crate::Core;

use super::{AcmeError, AcmeProvider};

impl Core {
    pub(crate) async fn load_cert(
        &self,
        provider: &AcmeProvider,
    ) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists(provider, "cert", provider.domains.as_slice())
            .await
            .map_err(AcmeError::CertCacheLoad)
    }

    pub(crate) async fn store_cert(
        &self,
        provider: &AcmeProvider,
        cert: &[u8],
    ) -> Result<(), AcmeError> {
        self.write(provider, "cert", provider.domains.as_slice(), cert)
            .await
            .map_err(AcmeError::CertCacheStore)
    }

    pub(crate) async fn load_account(
        &self,
        provider: &AcmeProvider,
    ) -> Result<Option<Vec<u8>>, AcmeError> {
        self.read_if_exists(provider, "account-key", provider.contact.as_slice())
            .await
            .map_err(AcmeError::AccountCacheLoad)
    }

    pub(crate) async fn store_account(
        &self,
        provider: &AcmeProvider,
        account: &[u8],
    ) -> Result<(), AcmeError> {
        self.write(
            provider,
            "account-key",
            provider.contact.as_slice(),
            account,
        )
        .await
        .map_err(AcmeError::AccountCacheStore)
    }

    async fn read_if_exists(
        &self,
        provider: &AcmeProvider,
        class: &str,
        items: &[String],
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self
            .storage
            .config
            .get(self.build_key(provider, class, items))
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
        provider: &AcmeProvider,
        class: &str,
        items: &[String],
        contents: impl AsRef<[u8]>,
    ) -> Result<(), std::io::Error> {
        self.storage
            .config
            .set([ConfigKey {
                key: self.build_key(provider, class, items),
                value: URL_SAFE_NO_PAD.encode(contents.as_ref()),
            }])
            .await
            .map_err(|err| std::io::Error::new(ErrorKind::Other, err))
    }

    fn build_key(&self, provider: &AcmeProvider, class: &str, _: &[String]) -> String {
        /*let mut ctx = Context::new(&SHA512);
        for el in items {
            ctx.update(el.as_ref());
            ctx.update(&[0])
        }
        ctx.update(provider.directory_url.as_bytes());

        format!(
            "certificate.acme-{}-{}.{}",
            provider.id,
            URL_SAFE_NO_PAD.encode(ctx.finish()),
            class
        )*/

        format!("acme.{}.{}", provider.id, class)
    }
}
