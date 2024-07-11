/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use trc::AddContext;
use utils::config::ConfigKey;

use crate::Core;

use super::AcmeProvider;

impl Core {
    pub(crate) async fn load_cert(&self, provider: &AcmeProvider) -> trc::Result<Option<Vec<u8>>> {
        self.read_if_exists(provider, "cert", provider.domains.as_slice())
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .details("Failed to load certificates")
            })
    }

    pub(crate) async fn store_cert(&self, provider: &AcmeProvider, cert: &[u8]) -> trc::Result<()> {
        self.write(provider, "cert", provider.domains.as_slice(), cert)
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .details("Failed to store certificate")
            })
    }

    pub(crate) async fn load_account(
        &self,
        provider: &AcmeProvider,
    ) -> trc::Result<Option<Vec<u8>>> {
        self.read_if_exists(provider, "account-key", provider.contact.as_slice())
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .details("Failed to load account")
            })
    }

    pub(crate) async fn store_account(
        &self,
        provider: &AcmeProvider,
        account: &[u8],
    ) -> trc::Result<()> {
        self.write(
            provider,
            "account-key",
            provider.contact.as_slice(),
            account,
        )
        .await
        .add_context(|err| {
            err.caused_by(trc::location!())
                .details("Failed to store account")
        })
    }

    async fn read_if_exists(
        &self,
        provider: &AcmeProvider,
        class: &str,
        items: &[String],
    ) -> trc::Result<Option<Vec<u8>>> {
        if let Some(content) = self
            .storage
            .config
            .get(self.build_key(provider, class, items))
            .await?
        {
            URL_SAFE_NO_PAD
                .decode(content.as_bytes())
                .map_err(Into::into)
                .map(Some)
        } else {
            Ok(None)
        }
    }

    async fn write(
        &self,
        provider: &AcmeProvider,
        class: &str,
        items: &[String],
        contents: impl AsRef<[u8]>,
    ) -> trc::Result<()> {
        self.storage
            .config
            .set([ConfigKey {
                key: self.build_key(provider, class, items),
                value: URL_SAFE_NO_PAD.encode(contents.as_ref()),
            }])
            .await
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
