/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
