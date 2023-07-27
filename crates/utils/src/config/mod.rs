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

pub mod certificate;
pub mod dynvalue;
pub mod listener;
pub mod parser;
pub mod utils;

use std::{collections::BTreeMap, fmt::Display, net::SocketAddr, time::Duration};

use rustls::ServerConfig;
use tokio::net::TcpSocket;

use crate::{failed, UnwrapFailure};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub keys: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub internal_id: u16,
    pub hostname: String,
    pub data: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<Listener>,
    pub tls: Option<ServerConfig>,
    pub tls_implicit: bool,
    pub max_connections: u64,
}

pub struct Servers {
    pub inner: Vec<Server>,
}

#[derive(Debug)]
pub struct Listener {
    pub socket: TcpSocket,
    pub addr: SocketAddr,
    pub ttl: Option<u32>,
    pub backlog: Option<u32>,
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

#[derive(Debug, Clone)]
pub enum DynValue {
    String(String),
    Position(usize),
    List(Vec<DynValue>),
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

        Config::parse(
            &std::fs::read_to_string(
                config_path.failed("Missing parameter --config=<path-to-config>."),
            )
            .failed("Could not read configuration file"),
        )
        .failed("Invalid configuration file")
    }
}
