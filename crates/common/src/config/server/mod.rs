/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, net::SocketAddr, sync::Arc, time::Duration};

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use tokio::net::TcpSocket;
use utils::{config::ipmask::IpAddrMask, snowflake::SnowflakeIdGenerator};

use crate::listener::TcpAcceptor;

pub mod listener;
pub mod tls;

#[derive(Default)]
pub struct Servers {
    pub servers: Vec<Server>,
    pub tcp_acceptors: AHashMap<String, TcpAcceptor>,
}

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<Listener>,
    pub proxy_networks: Vec<IpAddrMask>,
    pub max_connections: u64,
    pub id_generator: Arc<SnowflakeIdGenerator>,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default, Serialize, Deserialize)]
pub enum ServerProtocol {
    #[default]
    Smtp,
    Lmtp,
    Imap,
    Pop3,
    Http,
    ManageSieve,
}

impl ServerProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServerProtocol::Smtp => "smtp",
            ServerProtocol::Lmtp => "lmtp",
            ServerProtocol::Imap => "imap",
            ServerProtocol::Http => "http",
            ServerProtocol::Pop3 => "pop3",
            ServerProtocol::ManageSieve => "managesieve",
        }
    }
}

impl Display for ServerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ServerProtocol> for trc::Value {
    fn from(value: ServerProtocol) -> Self {
        trc::Value::Protocol(match value {
            ServerProtocol::Smtp => trc::Protocol::Smtp,
            ServerProtocol::Lmtp => trc::Protocol::Lmtp,
            ServerProtocol::Imap => trc::Protocol::Imap,
            ServerProtocol::Pop3 => trc::Protocol::Pop3,
            ServerProtocol::Http => trc::Protocol::Http,
            ServerProtocol::ManageSieve => trc::Protocol::ManageSieve,
        })
    }
}
