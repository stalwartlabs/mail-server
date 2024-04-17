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

use std::sync::Arc;

use rustls::{
    crypto::ring::sign::any_ecdsa_type,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use store::write::Bincode;

use crate::{listener::acme::directory::SerializedCert, Core};

use super::{directory::ACME_TLS_ALPN_NAME, AcmeProvider, StaticResolver};

impl Core {
    pub(crate) fn set_cert(&self, provider: &AcmeProvider, cert: Arc<CertifiedKey>) {
        // Add certificates
        let mut certificates = self.tls.certificates.load().as_ref().clone();
        for domain in provider.domains.iter() {
            certificates.insert(
                domain
                    .strip_prefix("*.")
                    .unwrap_or(domain.as_str())
                    .to_string(),
                cert.clone(),
            );
        }

        // Add default certificate
        if provider.default {
            certificates.insert("*".to_string(), cert);
        }

        self.tls.certificates.store(certificates.into());
    }
}

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.key.clone()
    }
}

pub(crate) fn build_acme_static_resolver(key: Option<Arc<CertifiedKey>>) -> Arc<ServerConfig> {
    let mut challenge = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(StaticResolver { key }));
    challenge.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
    Arc::new(challenge)
}

impl Core {
    pub(crate) async fn build_acme_certificate(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        match self
            .storage
            .lookup
            .key_get::<Bincode<SerializedCert>>(format!("acme:{domain}").into_bytes())
            .await
        {
            Ok(Some(cert)) => {
                match any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    cert.inner.private_key,
                ))) {
                    Ok(key) => Some(Arc::new(CertifiedKey::new(
                        vec![CertificateDer::from(cert.inner.certificate)],
                        key,
                    ))),
                    Err(err) => {
                        tracing::error!(
                            context = "acme",
                            event = "error",
                            domain = %domain,
                            reason = %err,
                            "Failed to parse private key",
                        );
                        None
                    }
                }
            }
            Err(err) => {
                tracing::error!(
                    context = "acme",
                    event = "error",
                    domain = %domain,
                    reason = %err,
                    "Failed to lookup token",
                );
                None
            }
            Ok(None) => {
                tracing::debug!(
                    context = "acme",
                    event = "error",
                    domain = %domain,
                    reason = "missing-token",
                    "Token not found in lookup store"
                );
                None
            }
        }
    }
}

pub trait IsTlsAlpnChallenge {
    fn is_tls_alpn_challenge(&self) -> bool;
}

impl IsTlsAlpnChallenge for ClientHello<'_> {
    fn is_tls_alpn_challenge(&self) -> bool {
        self.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME])
    }
}
