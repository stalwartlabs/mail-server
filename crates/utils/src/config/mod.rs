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

use ahash::{AHashMap, AHashSet};
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

        // Extract macros and includes
        let mut keys = BTreeMap::new();
        let mut includes = AHashSet::new();
        let mut macros = AHashMap::new();

        for (key, value) in config.keys {
            if let Some(macro_name) = key.strip_prefix("macros.") {
                macros.insert(macro_name.to_ascii_lowercase(), value);
            } else if key.starts_with("include.files.") {
                includes.insert(value);
            } else {
                keys.insert(key, value);
            }
        }

        // Include files
        config.keys = keys;
        for mut include in includes {
            include.replace_macros("include.files", &macros);
            config
                .parse(&std::fs::read_to_string(&include).failed(&format!(
                    "Could not read included configuration file {include:?}"
                )))
                .failed(&format!("Invalid included configuration file {include:?}"));
        }

        // Replace macros
        for (key, value) in &mut config.keys {
            value.replace_macros(key, &macros);
        }

        config
    }

    pub fn update(&mut self, settings: Vec<(String, String)>) {
        self.keys.extend(settings);
    }
}

trait ReplaceMacros: Sized {
    fn replace_macros(&mut self, key: &str, macros: &AHashMap<String, String>);
}

impl ReplaceMacros for String {
    fn replace_macros(&mut self, key: &str, macros: &AHashMap<String, String>) {
        if self.contains("%{") {
            let mut result = String::with_capacity(self.len());
            let mut value = self.as_str();

            loop {
                if let Some((suffix, macro_name)) = value.split_once("%{") {
                    if !suffix.is_empty() {
                        result.push_str(suffix);
                    }
                    if let Some((macro_name, rest)) = macro_name.split_once("}%") {
                        if let Some(macro_value) = macros.get(&macro_name.to_ascii_lowercase()) {
                            result.push_str(macro_value);
                            value = rest;
                        } else {
                            failed(&format!("Unknown macro {macro_name:?} for key {key:?}"));
                        }
                    } else {
                        failed(&format!(
                            "Unterminated macro name {value:?} for key {key:?}"
                        ));
                    }
                } else {
                    result.push_str(value);
                    break;
                }
            }

            *self = result;
        }
    }
}
