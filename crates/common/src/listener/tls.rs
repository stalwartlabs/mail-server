/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    cmp::Ordering,
    fmt::{self, Formatter},
    sync::Arc,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    SupportedProtocolVersion,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{Accept, LazyConfigAcceptor};

use crate::{Core, SharedCore};

use super::{
    acme::{
        resolver::{build_acme_static_resolver, IsTlsAlpnChallenge},
        AcmeProvider,
    },
    SessionStream, TcpAcceptor, TcpAcceptorResult,
};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

#[derive(Default)]
pub struct TlsManager {
    pub certificates: ArcSwap<AHashMap<String, Arc<CertifiedKey>>>,
    pub acme_providers: AHashMap<String, AcmeProvider>,
    pub self_signed_cert: Option<Arc<CertifiedKey>>,
}

#[derive(Clone)]
pub struct CertificateResolver {
    pub core: SharedCore,
}

impl CertificateResolver {
    pub fn new(core: SharedCore) -> Self {
        Self { core }
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.core
            .as_ref()
            .load()
            .resolve_certificate(hello.server_name())
    }
}

impl Core {
    pub(crate) fn resolve_certificate(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let certs = self.tls.certificates.load();

        name.map_or_else(
            || certs.get("*"),
            |name| {
                certs
                    .get(name)
                    .or_else(|| {
                        // Try with a wildcard certificate
                        name.split_once('.')
                            .and_then(|(_, domain)| certs.get(domain))
                    })
                    .or_else(|| {
                        tracing::debug!(
                            context = "tls",
                            event = "not-found",
                            client_name = name,
                            "No SNI certificate found by name, using default."
                        );
                        certs.get("*")
                    })
            },
        )
        .or_else(|| match certs.len().cmp(&1) {
            Ordering::Equal => certs.values().next(),
            Ordering::Greater => {
                tracing::debug!(
                    context = "tls",
                    event = "error",
                    "Multiple certificates available and no default certificate configured."
                );
                certs.values().next()
            }
            Ordering::Less => {
                tracing::warn!(
                    context = "tls",
                    event = "error",
                    "No certificates available, using self-signed."
                );
                self.tls.self_signed_cert.as_ref()
            }
        })
        .cloned()
    }
}

impl TcpAcceptor {
    pub async fn accept<IO>(
        &self,
        stream: IO,
        enable_acme: Option<Arc<Core>>,
    ) -> TcpAcceptorResult<IO>
    where
        IO: SessionStream,
    {
        match self {
            TcpAcceptor::Tls {
                config,
                acceptor,
                implicit,
            } if *implicit => match enable_acme {
                None => TcpAcceptorResult::Tls(acceptor.accept(stream)),
                Some(core) => {
                    match LazyConfigAcceptor::new(Default::default(), stream).await {
                        Ok(start_handshake) => {
                            if core.has_acme_tls_providers()
                                && start_handshake.client_hello().is_tls_alpn_challenge()
                            {
                                let key = match start_handshake.client_hello().server_name() {
                                    Some(domain) => {
                                        let key = core.build_acme_certificate(domain).await;

                                        tracing::trace!(
                                            context = "acme",
                                            event = "auth-key",
                                            domain = %domain,
                                            found_key = key.is_some(),
                                            "Client supplied SNI");
                                        key
                                    }
                                    None => {
                                        tracing::debug!(
                                            context = "acme",
                                            event = "error",
                                            reason = "missing-sni",
                                            "Client did not supply SNI"
                                        );
                                        None
                                    }
                                };

                                match start_handshake
                                    .into_stream(build_acme_static_resolver(key))
                                    .await
                                {
                                    Ok(mut tls) => {
                                        tracing::debug!(
                                            context = "acme",
                                            event = "validation",
                                            "Received TLS-ALPN-01 validation request."
                                        );
                                        let _ = tls.shutdown().await;
                                    }
                                    Err(err) => {
                                        tracing::info!(
                                            context = "acme",
                                            event = "error",
                                            error = ?err,
                                            "TLS-ALPN-01 validation request failed."
                                        );
                                    }
                                }
                            } else {
                                return TcpAcceptorResult::Tls(
                                    start_handshake.into_stream(config.clone()),
                                );
                            }
                        }
                        Err(err) => {
                            tracing::debug!(
                                context = "listener",
                                event = "error",
                                error = ?err,
                                "TLS handshake failed."
                            );
                        }
                    }

                    TcpAcceptorResult::Close
                }
            },
            _ => TcpAcceptorResult::Plain(stream),
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, TcpAcceptor::Tls { .. })
    }
}

impl<IO> TcpAcceptorResult<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub fn unwrap_tls(self) -> Accept<IO> {
        match self {
            TcpAcceptorResult::Tls(accept) => accept,
            _ => panic!("unwrap_tls called on non-TLS acceptor"),
        }
    }
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateResolver").finish()
    }
}

impl Clone for TlsManager {
    fn clone(&self) -> Self {
        Self {
            certificates: ArcSwap::from_pointee(self.certificates.load().as_ref().clone()),
            acme_providers: self.acme_providers.clone(),
            self_signed_cert: self.self_signed_cert.clone(),
        }
    }
}
