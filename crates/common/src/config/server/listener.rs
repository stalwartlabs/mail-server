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

use rustls::{
    crypto::ring::{default_provider, ALL_CIPHER_SUITES},
    server::ResolvesServerCert,
    ServerConfig, SupportedCipherSuite, ALL_VERSIONS,
};

use tokio::net::TcpSocket;
use tokio_rustls::TlsAcceptor;
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use crate::listener::{acme::directory::ACME_TLS_ALPN_NAME, tls::CertificateResolver, TcpAcceptor};

use super::{
    tls::{TLS12_VERSION, TLS13_VERSION},
    Listener, Server, ServerProtocol, Servers,
};

impl Servers {
    pub fn parse(config: &mut Config) -> Self {
        // Parse certificates and ACME managers
        let mut servers = Servers::default();
        servers.parse_certificates(config);
        servers.parse_acmes(config);

        // Parse servers
        let ids = config
            .sub_keys("server.listener", ".protocol")
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        for id in ids {
            servers.parse_server(config, id);
        }
        servers
    }

    fn parse_server(&mut self, config: &mut Config, id_: String) {
        // Parse protocol
        let id = id_.as_str();
        let protocol =
            if let Some(protocol) = config.property_require(("server.listener", id, "protocol")) {
                protocol
            } else {
                return;
            };

        // Build listeners
        let mut listeners = Vec::new();
        for (_, addr) in config.properties::<SocketAddr>(("server.listener", id, "bind")) {
            // Parse bind address and build socket
            let socket = match if addr.is_ipv4() {
                TcpSocket::new_v4()
            } else {
                TcpSocket::new_v6()
            } {
                Ok(socket) => socket,
                Err(err) => {
                    config.new_build_error(
                        ("server.listener", id, "bind"),
                        format!("Failed to create socket: {err}"),
                    );
                    return;
                }
            };

            // Set socket options
            for option in [
                "reuse-addr",
                "reuse-port",
                "send-buffer-size",
                "recv-buffer-size",
                "tos",
            ] {
                if let Some(value) = config.value_or_else(
                    ("server.listener", id, "socket", option),
                    ("server.socket", option),
                ) {
                    let value = value.to_string();
                    let key = ("server.listener", id, "socket", option);
                    let result = match option {
                        "reuse-addr" => socket
                            .set_reuseaddr(config.try_parse_value(key, &value).unwrap_or(true)),
                        #[cfg(not(target_env = "msvc"))]
                        "reuse-port" => socket
                            .set_reuseport(config.try_parse_value(key, &value).unwrap_or(false)),
                        "send-buffer-size" => {
                            if let Some(value) = config.try_parse_value(key, &value) {
                                socket.set_send_buffer_size(value)
                            } else {
                                continue;
                            }
                        }
                        "recv-buffer-size" => {
                            if let Some(value) = config.try_parse_value(key, &value) {
                                socket.set_recv_buffer_size(value)
                            } else {
                                continue;
                            }
                        }
                        "tos" => {
                            if let Some(value) = config.try_parse_value(key, &value) {
                                socket.set_tos(value)
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };

                    if let Err(err) = result {
                        config.new_build_error(key, format!("Failed to set socket option: {err}"));
                    }
                }
            }

            listeners.push(Listener {
                socket,
                addr,
                ttl: config
                    .property_or_else(("server.listener", id, "socket.ttl"), "server.socket.ttl"),
                backlog: config.property_or_else(
                    ("server.listener", id, "socket.backlog"),
                    "server.socket.backlog",
                ),
                linger: config.property_or_else(
                    ("server.listener", id, "socket.linger"),
                    "server.socket.linger",
                ),
                nodelay: config
                    .property_or_else(
                        ("server.listener", id, "socket.nodelay"),
                        "server.socket.nodelay",
                    )
                    .unwrap_or(true),
            });
        }

        if listeners.is_empty() {
            config.new_build_error(
                ("server.listener", id),
                "No 'bind' directive found for listener",
            );
            return;
        }

        // Build TLS config
        let (acceptor, tls_implicit) = if config
            .property_or_else(("server.listener", id, "tls.enable"), "server.tls.enable")
            .unwrap_or(false)
        {
            // Parse protocol versions
            let mut tls_v2 = true;
            let mut tls_v3 = true;
            let mut proto_err = None;
            for (_, protocol) in config.values_or_else(
                ("server.listener", id, "tls.disable-protocols"),
                "server.tls.disable-protocols",
            ) {
                match protocol {
                    "TLSv1.2" | "0x0303" => tls_v2 = false,
                    "TLSv1.3" | "0x0304" => tls_v3 = false,
                    protocol => {
                        proto_err = format!("Unsupported TLS protocol {protocol:?}").into();
                    }
                }
            }

            if let Some(proto_err) = proto_err {
                config.new_parse_error(("server.listener", id, "tls.disable-protocols"), proto_err);
            }

            // Parse cipher suites
            let mut disabled_ciphers: Vec<SupportedCipherSuite> = Vec::new();
            let cipher_keys = if config.has_prefix(("server.listener", id, "tls.disable-ciphers")) {
                ("server.listener", id, "tls.disable-ciphers").as_key()
            } else {
                "server.tls.disable-ciphers".as_key()
            };
            for (_, protocol) in config.properties::<SupportedCipherSuite>(cipher_keys) {
                disabled_ciphers.push(protocol);
            }

            // Build resolver
            let mut acme_acceptor = None;
            let resolver: Arc<dyn ResolvesServerCert> = if let Some(acme_id) =
                config.value_or_else(("server.listener", id, "tls.acme"), "server.tls.acme")
            {
                let acme = if let Some(acme) = self.acme_managers.get(acme_id) {
                    acme
                } else {
                    config.new_parse_error(
                        ("server.listener", id, "tls.acme"),
                        format!("Undefined ACME manager id {acme_id:?}"),
                    );
                    return;
                };

                // Check if this port is used to receive ACME challenges
                let port_key = ("acme", acme_id, "port").as_key();
                let acme_port = config
                    .property_or_default::<u16>(port_key, "443")
                    .unwrap_or(443);
                if listeners.iter().any(|l| l.addr.port() == acme_port) {
                    acme_acceptor = Some(acme.clone());
                }

                acme.clone()
            } else if let Some(cert) = config
                .value_or_else(
                    ("server.listener", id, "tls.certificate"),
                    "server.tls.certificate",
                )
                .and_then(|cert_id| self.certificates.get(cert_id))
                .cloned()
            {
                Arc::new(CertificateResolver {
                    sni: self.certificates_sni.clone(),
                    cert,
                })
            } else {
                config.new_parse_error(
                    ("server.listener", id, "tls.certificate"),
                    "Undefined certificate id",
                );
                return;
            };

            // Build cert provider
            let mut provider = default_provider();
            if !disabled_ciphers.is_empty() {
                provider.cipher_suites = ALL_CIPHER_SUITES
                    .iter()
                    .filter(|suite| !disabled_ciphers.contains(suite))
                    .copied()
                    .collect();
            }

            // Build server config
            let mut server_config = match ServerConfig::builder_with_provider(provider.into())
                .with_protocol_versions(if tls_v3 == tls_v2 {
                    ALL_VERSIONS
                } else if tls_v3 {
                    TLS13_VERSION
                } else {
                    TLS12_VERSION
                }) {
                Ok(server_config) => server_config
                    .with_no_client_auth()
                    .with_cert_resolver(resolver.clone()),
                Err(err) => {
                    config.new_build_error(
                        ("server.listener", id, "tls"),
                        format!("Failed to build TLS server config: {err}"),
                    );
                    return;
                }
            };

            server_config.ignore_client_order = config
                .property_or_else(
                    ("server.listener", id, "tls.ignore-client-order"),
                    "server.tls.ignore-client-order",
                )
                .unwrap_or(true);

            // Build acceptor
            let acceptor = if let Some(manager) = acme_acceptor {
                let mut challenge = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(resolver);
                challenge.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
                TcpAcceptor::Acme {
                    challenge: Arc::new(challenge),
                    default: Arc::new(server_config),
                    manager,
                }
            } else {
                TcpAcceptor::Tls(TlsAcceptor::from(Arc::new(server_config)))
            };

            (
                acceptor,
                config
                    .property_or_else(
                        ("server.listener", id, "tls.implicit"),
                        "server.tls.implicit",
                    )
                    .unwrap_or(true),
            )
        } else {
            (TcpAcceptor::Plain, false)
        };

        // Parse proxy networks
        let mut proxy_networks = Vec::new();
        let proxy_keys = if config.has_prefix(("server.listener", id, "proxy.trusted-networks")) {
            ("server.listener", id, "proxy.trusted-networks").as_key()
        } else {
            "server.proxy.trusted-networks".as_key()
        };
        for (_, network) in config.properties(proxy_keys) {
            proxy_networks.push(network);
        }

        self.servers.push(Server {
            max_connections: config
                .property_or_else(
                    ("server.listener", id, "max-connections"),
                    "server.max-connections",
                )
                .unwrap_or(8192),
            id: id_,
            protocol,
            listeners,
            acceptor,
            tls_implicit,
            proxy_networks,
        });
    }
}

impl ParseValue for ServerProtocol {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
        if value.eq_ignore_ascii_case("smtp") {
            Ok(Self::Smtp)
        } else if value.eq_ignore_ascii_case("lmtp") {
            Ok(Self::Lmtp)
        } else if value.eq_ignore_ascii_case("imap") {
            Ok(Self::Imap)
        } else if value.eq_ignore_ascii_case("http") | value.eq_ignore_ascii_case("https") {
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
