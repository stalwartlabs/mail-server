use std::{net::IpAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use crate::config::ServerProtocol;

use self::limiter::{ConcurrencyLimiter, InFlight};

pub mod limiter;
pub mod listen;

pub struct ServerInstance {
    pub id: String,
    pub listener_id: u16,
    pub protocol: ServerProtocol,
    pub hostname: String,
    pub data: String,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub is_tls_implicit: bool,
    pub limiter: ConcurrencyLimiter,
    pub shutdown_rx: watch::Receiver<bool>,
}

pub struct SessionData<T: AsyncRead + AsyncWrite + Unpin + 'static> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub span: tracing::Span,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn(&self, session: SessionData<TcpStream>);
    fn max_concurrent(&self) -> u64;
}
