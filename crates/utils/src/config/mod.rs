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

pub mod cron;
pub mod if_block;
pub mod ipmask;
pub mod listener;
pub mod parser;
pub mod tls;
pub mod utils;

use std::{collections::BTreeMap, fmt::Display, net::SocketAddr, sync::Arc, time::Duration};

use ahash::AHashMap;
use tokio::net::TcpSocket;

use crate::{
    acme::AcmeManager,
    failed,
    listener::{tls::Certificate, TcpAcceptor},
    UnwrapFailure,
};

use self::ipmask::IpAddrMask;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    pub keys: BTreeMap<String, String>,
    pub missing: AHashMap<String, Option<String>>,
    pub errors: AHashMap<String, ConfigError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Parse(String),
    Build(String),
    Macro(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ConfigKey {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub internal_id: u16,
    pub hostname: String,
    pub data: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<Listener>,
    pub proxy_networks: Vec<IpAddrMask>,
    pub acceptor: TcpAcceptor,
    pub tls_implicit: bool,
    pub max_connections: u64,
}

#[derive(Default)]
pub struct Servers {
    pub inner: Vec<Server>,
    pub certificates: Vec<Arc<Certificate>>,
    pub acme_managers: Vec<Arc<AcmeManager>>,
}

#[derive(Debug)]
pub struct Listener {
    pub socket: TcpSocket,
    pub addr: SocketAddr,
    pub backlog: Option<u32>,

    // TCP options
    pub ttl: Option<u32>,
    pub linger: Option<Duration>,
    pub nodelay: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum ServerProtocol {
    #[default]
    Smtp,
    Lmtp,
    Jmap,
    Imap,
    Http,
    ManageSieve,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Rate {
    pub requests: u64,
    pub period: Duration,
}

impl Display for ServerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerProtocol::Smtp => write!(f, "smtp"),
            ServerProtocol::Lmtp => write!(f, "lmtp"),
            ServerProtocol::Jmap => write!(f, "jmap"),
            ServerProtocol::Imap => write!(f, "imap"),
            ServerProtocol::Http => write!(f, "http"),
            ServerProtocol::ManageSieve => write!(f, "managesieve"),
        }
    }
}

pub type Result<T> = std::result::Result<T, String>;

impl Config {
    pub fn init() -> Self {
        let mut config_path = None;
        let mut found_param = false;

        for arg in std::env::args().skip(1) {
            if let Some((key, value)) = arg.split_once('=') {
                if key.starts_with("--config") {
                    config_path = value.trim().to_string().into();
                    break;
                } else {
                    failed(&format!("Invalid command line argument: {key}"));
                }
            } else if found_param {
                config_path = arg.into();
                break;
            } else if arg.starts_with("--config") {
                found_param = true;
            } else {
                failed(&format!("Invalid command line argument: {arg}"));
            }
        }

        // Read main configuration file
        let mut config = Config::default();
        config
            .parse(
                &std::fs::read_to_string(
                    config_path.failed("Missing parameter --config=<path-to-config>."),
                )
                .failed("Could not read configuration file"),
            )
            .failed("Invalid configuration file");

        config
    }

    pub async fn resolve_macros(&mut self) {
        let mut replacements = AHashMap::new();
        'outer: for (key, value) in &self.keys {
            if value.contains("%{") && value.contains("}%") {
                let mut result = String::with_capacity(value.len());
                let mut snippet: &str = value.as_str();

                loop {
                    if let Some((suffix, macro_name)) = snippet.split_once("%{") {
                        if !suffix.is_empty() {
                            result.push_str(suffix);
                        }
                        if let Some((class, location, rest)) =
                            macro_name.split_once("}%").and_then(|(name, rest)| {
                                name.split_once(':')
                                    .map(|(class, location)| (class, location, rest))
                            })
                        {
                            match class {
                                "cfg" => {
                                    if let Some(value) = replacements
                                        .get(location)
                                        .or_else(|| self.keys.get(location))
                                    {
                                        result.push_str(value);
                                    } else {
                                        self.errors.insert(
                                            key.clone(),
                                            ConfigError::Macro(format!("Unknown key {location:?}")),
                                        );
                                    }
                                }
                                "env" => match std::env::var(location) {
                                    Ok(value) => {
                                        result.push_str(&value);
                                    }
                                    Err(_) => {
                                        self.errors.insert(
                                                key.clone(),
                                                ConfigError::Macro(format!(
                                                    "Failed to obtain environment variable {location:?}"
                                                )),
                                            );
                                    }
                                },
                                "file" => {
                                    let file_name = location.strip_prefix("//").unwrap_or(location);
                                    match tokio::fs::read(file_name).await {
                                        Ok(value) => match String::from_utf8(value) {
                                            Ok(value) => {
                                                result.push_str(&value);
                                            }
                                            Err(err) => {
                                                self.errors.insert(
                                                    key.clone(),
                                                    ConfigError::Macro(format!(
                                                        "Failed to read file {file_name:?}: {err}"
                                                    )),
                                                );
                                                continue 'outer;
                                            }
                                        },
                                        Err(err) => {
                                            self.errors.insert(
                                                key.clone(),
                                                ConfigError::Macro(format!(
                                                    "Failed to read file {file_name:?}: {err}"
                                                )),
                                            );
                                            continue 'outer;
                                        }
                                    }
                                }
                                "http" | "https" => {}
                                _ => {
                                    continue 'outer;
                                }
                            };

                            snippet = rest;
                        }
                    } else {
                        result.push_str(snippet);
                        break;
                    }
                }

                replacements.insert(key.clone(), result);
            }
        }

        if !replacements.is_empty() {
            for (key, value) in replacements {
                self.keys.insert(key, value);
            }
        }
    }

    pub fn update(&mut self, settings: Vec<(String, String)>) {
        self.keys.extend(settings);
    }
}
