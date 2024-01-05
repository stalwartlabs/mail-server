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

use std::{net::SocketAddr, sync::Arc};

use ahash::AHashMap;
use rustls::{
    crypto::ring::{
        cipher_suite::{
            TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        },
        default_provider,
    },
    server::ResolvesServerCert,
    ServerConfig, SupportedCipherSuite, ALL_VERSIONS,
};
use tokio::net::TcpSocket;
use tokio_rustls::TlsAcceptor;

use crate::{
    acme::{directory::ACME_TLS_ALPN_NAME, AcmeManager},
    listener::{
        tls::{Certificate, CertificateResolver},
        TcpAcceptor,
    },
    UnwrapFailure,
};

use super::{
    tls::{TLS12_VERSION, TLS13_VERSION},
    utils::{AsKey, ParseKey, ParseValue},
    Config, Listener, Server, ServerProtocol, Servers,
};

impl Config {
    pub fn parse_servers(&self) -> super::Result<Servers> {
        // Parse certificates and ACME managers
        let certificates = self.parse_certificates()?;
        let acmes = self.parse_acmes()?;

        // Parse servers
        let mut servers = Servers::default();
        for (internal_id, id) in self.sub_keys("server.listener").enumerate() {
            let mut server = self.parse_server(id, &certificates, &acmes)?;
            if !servers.inner.iter().any(|s| s.id == server.id) {
                server.internal_id = internal_id as u16;
                servers.inner.push(server);
            } else {
                return Err(format!("Duplicate listener id {:?}.", server.id));
            }
        }

        // Add certificates with valid paths
        for (id, cert) in certificates {
            if cert.path.len() == 2 {
                servers.certificates.push(cert);
            } else {
                tracing::debug!(
                    context = "config",
                    event = "acme",
                    id = id,
                    "Certificate reloading disabled for id {id:?}",
                );
            }
        }

        // Add ACME managers with configured domains
        for (id, acme) in acmes {
            if !acme.domains.is_empty() {
                servers.acme_managers.push(acme);
            } else {
                tracing::debug!(
                    context = "config",
                    event = "acme",
                    id = id,
                    "ACME certificate manager disabled for id {id:?}",
                );
            }
        }

        if !servers.inner.is_empty() {
            Ok(servers)
        } else {
            Err("No server directives found in config file.".to_string())
        }
    }

    fn parse_server(
        &self,
        id: &str,
        certificates: &AHashMap<String, Arc<Certificate>>,
        acmes: &AHashMap<String, Arc<AcmeManager>>,
    ) -> super::Result<Server> {
        // Build listeners
        let mut listeners = Vec::new();
        for result in self.properties::<SocketAddr>(("server.listener", id, "bind")) {
            // Parse bind address and build socket
            let (_, addr) = result?;
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            }
            .map_err(|err| format!("Failed to create socket: {err}"))?;

            // Set socket options
            for option in [
                "reuse-addr",
                "reuse-port",
                "send-buffer-size",
                "recv-buffer-size",
                "tos",
            ] {
                if let Some(value) = self.value_or_default(
                    ("server.listener", id, "socket", option),
                    ("server.socket", option),
                ) {
                    let key = ("server.listener", id, "socket", option);
                    match option {
                        "reuse-addr" => socket.set_reuseaddr(value.parse_key(key)?),
                        #[cfg(not(target_env = "msvc"))]
                        "reuse-port" => socket.set_reuseport(value.parse_key(key)?),
                        "send-buffer-size" => socket.set_send_buffer_size(value.parse_key(key)?),
                        "recv-buffer-size" => socket.set_recv_buffer_size(value.parse_key(key)?),
                        "tos" => socket.set_tos(value.parse_key(key)?),
                        _ => unreachable!(),
                    }
                    .map_err(|err| {
                        format!("Failed to set socket option '{option}' for listener '{id}': {err}")
                    })?;
                }
            }

            listeners.push(Listener {
                socket,
                addr,
                ttl: self.property_or_default(
                    ("server.listener", id, "socket.ttl"),
                    "server.socket.ttl",
                )?,
                backlog: self.property_or_default(
                    ("server.listener", id, "socket.backlog"),
                    "server.socket.backlog",
                )?,
                linger: self.property_or_default(
                    ("server.listener", id, "socket.linger"),
                    "server.socket.linger",
                )?,
                nodelay: self
                    .property_or_default(
                        ("server.listener", id, "socket.nodelay"),
                        "server.socket.nodelay",
                    )?
                    .unwrap_or(true),
            });
        }

        if listeners.is_empty() {
            return Err(format!("No 'bind' directive found for listener id {id:?}"));
        }

        // Build TLS config
        let (acceptor, tls_implicit) = if self
            .property_or_default(("server.listener", id, "tls.enable"), "server.tls.enable")?
            .unwrap_or(false)
        {
            // Parse protocol versions
            let mut tls_v2 = false;
            let mut tls_v3 = false;
            for (key, protocol) in self.values_or_default(
                ("server.listener", id, "tls.protocols"),
                "server.tls.protocols",
            ) {
                match protocol {
                    "TLSv1.2" | "0x0303" => tls_v2 = true,
                    "TLSv1.3" | "0x0304" => tls_v3 = true,
                    protocol => {
                        return Err(format!(
                            "Unsupported TLS protocol {protocol:?} found in key {key:?}",
                        ))
                    }
                }
            }

            // Parse cipher suites
            let mut ciphers: Vec<SupportedCipherSuite> = Vec::new();
            for (key, protocol) in
                self.values_or_default(("server.listener", id, "tls.ciphers"), "server.tls.ciphers")
            {
                ciphers.push(protocol.parse_key(key)?);
            }

            // Build resolver
            let mut acme_acceptor = None;
            let resolver: Arc<dyn ResolvesServerCert> = if let Some(acme_id) =
                self.value_or_default(("server.listener", id, "tls.acme"), "server.tls.acme")
            {
                let acme = acmes.get(acme_id).ok_or_else(|| {
                    format!("Undefined ACME id {acme_id:?} for listener {id:?}.",)
                })?;

                // Check if this port is used to receive ACME challenges
                let acme_port = self.property_or_static::<u16>(("acme", acme_id, "port"), "443")?;
                if listeners.iter().any(|l| l.addr.port() == acme_port) {
                    acme_acceptor = Some(acme.clone());
                }

                acme.clone()
            } else {
                let cert_id = self
                    .value_or_default(
                        ("server.listener", id, "tls.certificate"),
                        "server.tls.certificate",
                    )
                    .ok_or_else(|| format!("Undefined certificate id for listener {id:?}."))?;
                let mut resolver = CertificateResolver {
                    sni: Default::default(),
                    cert: certificates
                        .get(cert_id)
                        .ok_or_else(|| {
                            format!("Undefined certificate id {cert_id:?} for listener {id:?}.",)
                        })?
                        .clone(),
                };

                // Add SNI certificates
                for (key, value) in
                    self.values_or_default(("server.listener", id, "tls.sni"), "server.tls.sni")
                {
                    if let Some(prefix) = key.strip_suffix(".subject") {
                        resolver
                            .add(
                                value,
                                match self.value((prefix, "certificate")) {
                                    Some(sni_cert_id) if sni_cert_id != cert_id => {
                                        certificates.get(sni_cert_id).ok_or_else(|| {
                                            format!(
                                                "Undefined certificate id {sni_cert_id:?} for SNI {value:?} in listener {id:?}.",
                                            )
                                        })?.clone()
                                    }
                                    _ => resolver.cert.clone(),
                                },
                            )
                            .map_err(|err| {
                                format!("Failed to add SNI certificate for {key:?}: {err}")
                            })?;
                    }
                }

                Arc::new(resolver)
            };

            // Build cert provider
            let mut provider = default_provider();
            if !ciphers.is_empty() {
                provider.cipher_suites = ciphers;
            }

            // Build server config
            let mut config = ServerConfig::builder_with_provider(provider.into())
                .with_protocol_versions(if tls_v3 == tls_v2 {
                    ALL_VERSIONS
                } else if tls_v3 {
                    TLS13_VERSION
                } else {
                    TLS12_VERSION
                })
                .map_err(|err| format!("Failed to build TLS config: {err}"))?
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone());
            config.ignore_client_order = self
                .property_or_default(
                    ("server.listener", id, "tls.ignore-client-order"),
                    "server.tls.ignore-client-order",
                )?
                .unwrap_or(true);

            // Build acceptor
            let acceptor = if let Some(manager) = acme_acceptor {
                let mut challenge = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(resolver);
                challenge.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
                TcpAcceptor::Acme {
                    challenge: Arc::new(challenge),
                    default: Arc::new(config),
                    manager,
                }
            } else {
                TcpAcceptor::Tls(TlsAcceptor::from(Arc::new(config)))
            };

            (
                acceptor,
                self.property_or_default(
                    ("server.listener", id, "tls.implicit"),
                    "server.tls.implicit",
                )?
                .unwrap_or(true),
            )
        } else {
            (TcpAcceptor::Plain, false)
        };

        let protocol = self.property_require(("server.listener", id, "protocol"))?;

        Ok(Server {
            id: id.to_string(),
            internal_id: 0,
            hostname: self
                .value_or_default(("server.listener", id, "hostname"), "server.hostname")
                .ok_or("Hostname directive not found.")?
                .to_string(),
            data: match protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => self
                    .value_or_default(("server.listener", id, "greeting"), "server.greeting")
                    .unwrap_or(concat!(
                        "Stalwart SMTP v",
                        env!("CARGO_PKG_VERSION"),
                        " at your service."
                    ))
                    .to_string(),

                ServerProtocol::Jmap => self
                    .value_or_default(("server.listener", id, "url"), "server.url")
                    .failed(&format!("No 'url' directive found for listener {id:?}"))
                    .to_string(),
                ServerProtocol::Imap | ServerProtocol::Http | ServerProtocol::ManageSieve => self
                    .value_or_default(("server.listener", id, "url"), "server.url")
                    .unwrap_or_default()
                    .to_string(),
            },
            max_connections: self
                .property_or_default(
                    ("server.listener", id, "max-connections"),
                    "server.max-connections",
                )?
                .unwrap_or(8192),
            protocol,
            listeners,
            acceptor,
            tls_implicit,
        })
    }
}

impl ParseValue for ServerProtocol {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if value.eq_ignore_ascii_case("smtp") {
            Ok(Self::Smtp)
        } else if value.eq_ignore_ascii_case("lmtp") {
            Ok(Self::Lmtp)
        } else if value.eq_ignore_ascii_case("jmap") {
            Ok(Self::Jmap)
        } else if value.eq_ignore_ascii_case("imap") {
            Ok(Self::Imap)
        } else if value.eq_ignore_ascii_case("http") {
            Ok(Self::Http)
        } else if value.eq_ignore_ascii_case("managesieve") {
            Ok(Self::ManageSieve)
        } else {
            Err(format!(
                "Invalid server protocol type {:?} for property {:?}.",
                value,
                key.as_key()
            ))
        }
    }
}

impl ParseValue for SocketAddr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid socket address {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for SupportedCipherSuite {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            // TLS1.3 suites
            "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
            "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
            "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
            // TLS1.2 suites
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            cipher => {
                return Err(format!(
                    "Unsupported TLS cipher suite {:?} found in key {:?}",
                    cipher,
                    key.as_key()
                ))
            }
        })
    }
}
