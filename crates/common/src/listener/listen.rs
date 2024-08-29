/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use proxy_header::io::ProxiedStream;
use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::server::TlsStream;
use trc::{EventType, HttpEvent, ImapEvent, ManageSieveEvent, Pop3Event, SmtpEvent};
use utils::{config::Config, UnwrapFailure};

use crate::{
    config::server::{Listener, Server, ServerProtocol, Servers},
    Core,
};

use super::{
    limiter::ConcurrencyLimiter, ServerInstance, SessionData, SessionManager, SessionStream,
    TcpAcceptor,
};

impl Server {
    pub fn spawn(
        self,
        manager: impl SessionManager,
        core: Arc<ArcSwap<Core>>,
        acceptor: TcpAcceptor,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // Prepare instance
        let instance = Arc::new(ServerInstance {
            id: self.id,
            protocol: self.protocol,
            proxy_networks: self.proxy_networks,
            limiter: ConcurrencyLimiter::new(self.max_connections),
            acceptor,
            shutdown_rx,
            span_id_gen: self.span_id_gen,
        });
        let is_tls = matches!(instance.acceptor, TcpAcceptor::Tls { implicit, .. } if implicit);
        let is_https = is_tls && self.protocol == ServerProtocol::Http;
        let has_proxies = !instance.proxy_networks.is_empty();

        // Spawn listeners
        for listener in self.listeners {
            let local_addr = listener.addr;

            // Obtain TCP options
            let opts = SocketOpts {
                nodelay: listener.nodelay,
                ttl: listener.ttl,
                linger: listener.linger,
            };

            // Bind socket
            let listener = match listener.listen() {
                Ok(listener) => {
                    trc::event!(
                        Network(trc::NetworkEvent::ListenStart),
                        ListenerId = instance.id.clone(),
                        LocalIp = local_addr.ip(),
                        LocalPort = local_addr.port(),
                        Tls = is_tls,
                    );

                    listener
                }
                Err(err) => {
                    trc::event!(
                        Network(trc::NetworkEvent::ListenError),
                        ListenerId = instance.id.clone(),
                        LocalIp = local_addr.ip(),
                        LocalPort = local_addr.port(),
                        Tls = is_tls,
                        Reason = err,
                    );

                    continue;
                }
            };

            // Spawn listener
            let mut shutdown_rx = instance.shutdown_rx.clone();
            let manager = manager.clone();
            let instance = instance.clone();
            let core = core.clone();
            tokio::spawn(async move {
                let (span_start, span_end) = match self.protocol {
                    ServerProtocol::Smtp | ServerProtocol::Lmtp => (
                        EventType::Smtp(SmtpEvent::ConnectionStart),
                        EventType::Smtp(SmtpEvent::ConnectionEnd),
                    ),
                    ServerProtocol::Imap => (
                        EventType::Imap(ImapEvent::ConnectionStart),
                        EventType::Imap(ImapEvent::ConnectionEnd),
                    ),
                    ServerProtocol::Pop3 => (
                        EventType::Pop3(Pop3Event::ConnectionStart),
                        EventType::Pop3(Pop3Event::ConnectionEnd),
                    ),
                    ServerProtocol::Http => (
                        EventType::Http(HttpEvent::ConnectionStart),
                        EventType::Http(HttpEvent::ConnectionEnd),
                    ),
                    ServerProtocol::ManageSieve => (
                        EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
                        EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
                    ),
                };

                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    let core = core.as_ref().load_full();
                                    let enable_acme = (is_https && core.has_acme_tls_providers()).then_some(core.clone());

                                    if has_proxies && instance.proxy_networks.iter().any(|network| network.matches(&remote_addr.ip())) {
                                        let instance = instance.clone();
                                        let manager = manager.clone();

                                        // Set socket options
                                        opts.apply(&stream);

                                        tokio::spawn(async move {
                                            match ProxiedStream::create_from_tokio(stream, Default::default()).await {
                                                Ok(stream) =>{
                                                    let remote_addr = stream.proxy_header()
                                                                            .proxied_address()
                                                                            .map(|addr| addr.source)
                                                                            .unwrap_or(remote_addr);
                                                    if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &core) {
                                                        // Spawn session
                                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                                    }
                                                }
                                                Err(err) => {
                                                    trc::event!(
                                                        Network(trc::NetworkEvent::ProxyError),
                                                        ListenerId = instance.id.clone(),
                                                        LocalIp = local_addr.ip(),
                                                        LocalPort = local_addr.port(),
                                                        Tls = is_tls,
                                                        Reason = err.to_string(),
                                                    );
                                                }
                                            }
                                        });
                                    } else if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &core) {
                                        // Set socket options
                                        opts.apply(&session.stream);

                                        // Spawn session
                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                    }
                                }
                                Err(err) => {
                                    trc::event!(
                                        Network(trc::NetworkEvent::AcceptError),
                                        ListenerId = instance.id.clone(),
                                        LocalIp = local_addr.ip(),
                                        LocalPort = local_addr.port(),
                                        Tls = is_tls,
                                        Reason = err.to_string(),
                                    );
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {

                            trc::event!(
                                Network(trc::NetworkEvent::ListenStop),
                                ListenerId = instance.id.clone(),
                                LocalIp = local_addr.ip(),
                                Tls = is_tls,
                                LocalPort = local_addr.port(),
                            );

                            manager.shutdown().await;
                            break;
                        }
                    };
                }
            });
        }
    }
}

trait BuildSession {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        core: &Core,
    ) -> Option<SessionData<T>>;
}

impl BuildSession for Arc<ServerInstance> {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        core: &Core,
    ) -> Option<SessionData<T>> {
        // Convert mapped IPv6 addresses to IPv4
        let remote_ip = match remote_addr.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            remote_ip => remote_ip,
        };
        let remote_port = remote_addr.port();

        // Check if blocked
        if core.is_ip_blocked(&remote_ip) {
            trc::event!(
                Security(trc::SecurityEvent::IpBlocked),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
            );
            None
        } else if let Some(in_flight) = self.limiter.is_allowed() {
            // Enforce concurrency
            SessionData {
                stream,
                in_flight,
                local_ip: local_addr.ip(),
                local_port: local_addr.port(),
                session_id: 0,
                remote_ip,
                remote_port,
                protocol: self.protocol,
                instance: self.clone(),
            }
            .into()
        } else {
            trc::event!(
                Limit(trc::LimitEvent::ConcurrentConnection),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
                Limit = self.limiter.max_concurrent,
            );

            None
        }
    }
}

pub struct SocketOpts {
    pub nodelay: bool,
    pub ttl: Option<u32>,
    pub linger: Option<Duration>,
}

impl SocketOpts {
    pub fn apply(&self, stream: &TcpStream) {
        // Set TCP options
        if let Err(err) = stream.set_nodelay(self.nodelay) {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_string(),
                Details = "Failed to set TCP_NODELAY",
            );
        }
        if let Some(ttl) = self.ttl {
            if let Err(err) = stream.set_ttl(ttl) {
                trc::event!(
                    Network(trc::NetworkEvent::SetOptError),
                    Reason = err.to_string(),
                    Details = "Failed to set TTL",
                );
            }
        }
        if self.linger.is_some() {
            if let Err(err) = stream.set_linger(self.linger) {
                trc::event!(
                    Network(trc::NetworkEvent::SetOptError),
                    Reason = err.to_string(),
                    Details = "Failed to set LINGER",
                );
            }
        }
    }
}

impl Servers {
    pub fn bind_and_drop_priv(&self, config: &mut Config) {
        // Bind as root
        for server in &self.servers {
            for listener in &server.listeners {
                if let Err(err) = listener.socket.bind(listener.addr) {
                    config.new_build_error(
                        format!("server.listener.{}", server.id),
                        format!("Failed to bind to {}: {}", listener.addr, err),
                    );
                }
            }
        }

        // Drop privileges
        #[cfg(not(target_env = "msvc"))]
        {
            if let Ok(run_as_user) = std::env::var("RUN_AS_USER") {
                let mut pd = privdrop::PrivDrop::default().user(run_as_user);
                if let Ok(run_as_group) = std::env::var("RUN_AS_GROUP") {
                    pd = pd.group(run_as_group);
                }
                pd.apply().failed("Failed to drop privileges");
            }
        }
    }

    pub fn spawn(
        mut self,
        spawn: impl Fn(Server, TcpAcceptor, watch::Receiver<bool>),
    ) -> (watch::Sender<bool>, watch::Receiver<bool>) {
        // Spawn listeners
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        for server in self.servers {
            let acceptor = self
                .tcp_acceptors
                .remove(&server.id)
                .unwrap_or(TcpAcceptor::Plain);

            spawn(server, acceptor, shutdown_rx.clone());
        }
        (shutdown_tx, shutdown_rx)
    }
}

impl Listener {
    pub fn listen(self) -> Result<TcpListener, String> {
        self.socket
            .listen(self.backlog.unwrap_or(1024))
            .map_err(|err| format!("Failed to listen on {}: {}", self.addr, err))
    }
}

impl ServerInstance {
    pub async fn tls_accept<T: SessionStream>(
        &self,
        stream: T,
        session_id: u64,
    ) -> Result<TlsStream<T>, ()> {
        match &self.acceptor {
            TcpAcceptor::Tls { acceptor, .. } => match acceptor.accept(stream).await {
                Ok(stream) => {
                    trc::event!(
                        Tls(trc::TlsEvent::Handshake),
                        ListenerId = self.id.clone(),
                        SpanId = session_id,
                        Version = format!(
                            "{:?}",
                            stream
                                .get_ref()
                                .1
                                .protocol_version()
                                .unwrap_or(rustls::ProtocolVersion::TLSv1_3)
                        ),
                        Details = format!(
                            "{:?}",
                            stream
                                .get_ref()
                                .1
                                .negotiated_cipher_suite()
                                .unwrap_or(TLS13_AES_128_GCM_SHA256)
                        )
                    );
                    Ok(stream)
                }
                Err(err) => {
                    trc::event!(
                        Tls(trc::TlsEvent::HandshakeError),
                        ListenerId = self.id.clone(),
                        SpanId = session_id,
                        Reason = err.to_string(),
                    );
                    Err(())
                }
            },
            TcpAcceptor::Plain => {
                trc::event!(
                    Tls(trc::TlsEvent::NotConfigured),
                    ListenerId = self.id.clone(),
                    SpanId = session_id,
                );
                Err(())
            }
        }
    }
}
