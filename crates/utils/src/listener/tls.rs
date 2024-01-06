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
    fmt::{self, Formatter},
    path::PathBuf,
    sync::Arc,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use rustls::{
    client::verify_server_name,
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    Error, SupportedProtocolVersion,
};
use rustls_pki_types::{DnsName, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{Accept, LazyConfigAcceptor, TlsAcceptor};

use crate::{acme::resolver::IsTlsAlpnChallenge, config::tls::build_certified_key};

use super::{SessionStream, TcpAcceptor, TcpAcceptorResult};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

pub struct CertificateResolver {
    pub sni: AHashMap<String, Arc<Certificate>>,
    pub cert: Arc<Certificate>,
}

pub struct Certificate {
    pub cert: ArcSwap<CertifiedKey>,
    pub path: Vec<PathBuf>,
}

impl CertificateResolver {
    pub fn add(&mut self, name: &str, ck: Arc<Certificate>) -> Result<(), Error> {
        let server_name = {
            let checked_name = DnsName::try_from(name)
                .map_err(|_| Error::General("Bad DNS name".into()))
                .map(|name| name.to_lowercase_owned())?;
            ServerName::DnsName(checked_name)
        };

        ck.cert
            .load()
            .end_entity_cert()
            .and_then(ParsedCertificate::try_from)
            .and_then(|cert| verify_server_name(&cert, &server_name))?;

        if let ServerName::DnsName(name) = server_name {
            self.sni.insert(name.as_ref().to_string(), ck);
        }
        Ok(())
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !self.sni.is_empty() {
            if let Some(cert) = hello.server_name().and_then(|name| self.sni.get(name)) {
                return cert.cert.load().clone().into();
            }
        }
        self.cert.cert.load().clone().into()
    }
}

impl TcpAcceptor {
    pub async fn accept<IO>(&self, stream: IO) -> TcpAcceptorResult<IO>
    where
        IO: SessionStream,
    {
        match self {
            TcpAcceptor::Tls(acceptor) => TcpAcceptorResult::Tls(acceptor.accept(stream)),
            TcpAcceptor::Acme {
                challenge,
                default,
                manager,
            } => {
                if manager.has_order_in_progress() {
                    match LazyConfigAcceptor::new(Default::default(), stream).await {
                        Ok(start_handshake) => {
                            if start_handshake.client_hello().is_tls_alpn_challenge() {
                                match start_handshake.into_stream(challenge.clone()).await {
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
                                    start_handshake.into_stream(default.clone()),
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
                } else {
                    TcpAcceptorResult::Tls(TlsAcceptor::from(default.clone()).accept(stream))
                }
            }
            TcpAcceptor::Plain => TcpAcceptorResult::Plain(stream),
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self, TcpAcceptor::Tls(_) | TcpAcceptor::Acme { .. })
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

impl Certificate {
    pub async fn reload(&self) -> crate::config::Result<()> {
        let cert = build_certified_key(
            tokio::fs::read(&self.path[0]).await.map_err(|err| {
                format!(
                    "Failed to read certificate from path {id:?}: {err}",
                    id = self.path[0]
                )
            })?,
            tokio::fs::read(&self.path[1]).await.map_err(|err| {
                format!(
                    "Failed to read private key from path {id:?}: {err}",
                    id = self.path[1]
                )
            })?,
            "certificate",
        )?;

        self.cert.store(Arc::new(cert));

        Ok(())
    }
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateResolver")
            .field("sni", &self.sni.keys())
            .field("cert", &self.cert.path)
            .finish()
    }
}
