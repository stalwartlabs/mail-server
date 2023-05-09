/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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
pub mod listener;
pub mod parser;
pub mod utils;

use std::{collections::BTreeMap, fmt::Display, net::SocketAddr, time::Duration};

use rustls::ServerConfig;
use tokio::net::TcpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    keys: BTreeMap<String, String>,
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
        }
    }
}

pub type Result<T> = std::result::Result<T, String>;
