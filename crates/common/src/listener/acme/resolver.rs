/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
use trc::AcmeEvent;

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
                        trc::event!(
                            Acme(AcmeEvent::Error),
                            Name = domain.to_string(),
                            Reason = err.to_string(),
                            Details = "Failed to parse private key"
                        );
                        None
                    }
                }
            }
            Err(err) => {
                trc::event!(
                    Acme(AcmeEvent::Error),
                    Name = domain.to_string(),
                    CausedBy = err
                );
                None
            }
            Ok(None) => {
                trc::event!(Acme(AcmeEvent::TokenNotFound), Name = domain.to_string());
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
