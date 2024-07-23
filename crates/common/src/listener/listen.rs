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
        });
        let is_tls = matches!(instance.acceptor, TcpAcceptor::Tls { implicit, .. } if implicit);
        let is_https = is_tls && self.protocol == ServerProtocol::Http;
        let has_proxies = !instance.proxy_networks.is_empty();

        // Spawn listeners
        for listener in self.listeners {
            tracing::info!(
                id = instance.id,
                protocol = ?instance.protocol,
                bind.ip = listener.addr.ip().to_string(),
                bind.port = listener.addr.port(),
                tls = is_tls,
                "Starting listener"
            );
            let local_addr = listener.addr;

            // Obtain TCP options
            let opts = SocketOpts {
                nodelay: listener.nodelay,
                ttl: listener.ttl,
                linger: listener.linger,
            };

            // Bind socket
            let listener = match listener.listen() {
                Ok(listener) => listener,
                Err(err) => {
                    tracing::error!(
                        event = "error",
                        instance = instance.id,
                        protocol = ?instance.protocol,
                        reason = %err,
                        "Failed to bind listener"
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
                                                        manager.spawn(session, is_tls, enable_acme);
                                                    }
                                                }
                                                Err(err) => {
                                                    tracing::trace!(context = "io",
                                                                    event = "error",
                                                                    instance = instance.id,
                                                                    protocol = ?instance.protocol,
                                                                    reason = %err,
                                                                    "Failed to accept proxied TCP connection");
                                                }
                                            }
                                        });
                                    } else if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &core) {
                                        // Set socket options
                                        opts.apply(&session.stream);

                                        // Spawn session
                                        manager.spawn(session, is_tls, enable_acme);
                                    }
                                }
                                Err(err) => {
                                    tracing::trace!(context = "io",
                                                    event = "error",
                                                    instance = instance.id,
                                                    protocol = ?instance.protocol,
                                                    "Failed to accept TCP connection: {}", err);
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(
                                event = "shutdown",
                                instance = instance.id,
                                protocol = ?instance.protocol,
                                "Listener shutting down.");
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
            tracing::debug!(
                context = "listener",
                event = "blocked",
                instance = self.id,
                protocol = ?self.protocol,
                remote.ip = remote_ip.to_string(),
                remote.port = remote_port,
                "Dropping connection from blocked IP."
            );
            None
        } else if let Some(in_flight) = self.limiter.is_allowed() {
            let todo = "build session id";
            let span = tracing::info_span!(
                "session",
                instance = self.id,
                protocol = ?self.protocol,
                remote.ip = remote_ip.to_string(),
                remote.port = remote_port,
            );
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
            tracing::info!(
                context = "throttle",
                event = "too-many-requests",
                instance = self.id,
                protocol = ?self.protocol,
                remote.ip = remote_ip.to_string(),
                remote.port = remote_port,
                max_concurrent = self.limiter.max_concurrent,
                "Too many concurrent connections."
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
            tracing::warn!(
                context = "tcp",
                event = "error",
                "Failed to set no-delay: {}",
                err
            );
        }
        if let Some(ttl) = self.ttl {
            if let Err(err) = stream.set_ttl(ttl) {
                tracing::warn!(
                    context = "tcp",
                    event = "error",
                    "Failed to set TTL: {}",
                    err
                );
            }
        }
        if self.linger.is_some() {
            if let Err(err) = stream.set_linger(self.linger) {
                tracing::warn!(
                    context = "tcp",
                    event = "error",
                    "Failed to set linger: {}",
                    err
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
                    tracing::info!(
                        context = "tls",
                        event = "handshake",
                        version = ?stream.get_ref().1.protocol_version().unwrap_or(rustls::ProtocolVersion::TLSv1_3),
                        cipher = ?stream.get_ref().1.negotiated_cipher_suite().unwrap_or(TLS13_AES_128_GCM_SHA256),
                    );
                    Ok(stream)
                }
                Err(err) => {
                    tracing::debug!(
                        context = "tls",
                        event = "error",
                        "Failed to accept TLS connection: {}",
                        err
                    );
                    Err(())
                }
            },
            TcpAcceptor::Plain => {
                tracing::debug!(
                    context = "tls",
                    event = "error",
                    "Failed to accept TLS connection: {}",
                    "TLS is not configured for this server."
                );
                Err(())
            }
        }
    }
}
