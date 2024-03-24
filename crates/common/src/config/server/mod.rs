use std::{fmt::Display, net::SocketAddr, sync::Arc, time::Duration};

use ahash::AHashMap;
use tokio::net::TcpSocket;
use utils::config::ipmask::IpAddrMask;

use crate::listener::{acme::AcmeManager, tls::Certificate, TcpAcceptor};

pub mod listener;
pub mod tls;

#[derive(Default)]
pub struct Servers {
    pub servers: Vec<Server>,
    pub certificates: AHashMap<String, Arc<Certificate>>,
    pub certificates_sni: AHashMap<String, Arc<Certificate>>,
    pub acme_managers: AHashMap<String, Arc<AcmeManager>>,
}

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<Listener>,
    pub proxy_networks: Vec<IpAddrMask>,
    pub acceptor: TcpAcceptor,
    pub tls_implicit: bool,
    pub max_connections: u64,
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
    Imap,
    Http,
    ManageSieve,
}

impl Display for ServerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerProtocol::Smtp => write!(f, "smtp"),
            ServerProtocol::Lmtp => write!(f, "lmtp"),
            ServerProtocol::Imap => write!(f, "imap"),
            ServerProtocol::Http => write!(f, "http"),
            ServerProtocol::ManageSieve => write!(f, "managesieve"),
        }
    }
}
