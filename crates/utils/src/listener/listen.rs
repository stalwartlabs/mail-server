use std::sync::Arc;

use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::{Config, Listener, Server, ServerProtocol, Servers},
    failed,
    listener::SessionData,
    UnwrapFailure,
};

use super::{limiter::ConcurrencyLimiter, ServerInstance, SessionManager};

impl Server {
    pub fn spawn(self, manager: impl SessionManager, shutdown_rx: watch::Receiver<bool>) {
        // Prepare instance
        let instance = Arc::new(ServerInstance {
            data: if matches!(self.protocol, ServerProtocol::Smtp | ServerProtocol::Lmtp) {
                format!("220 {} {}\r\n", self.hostname, self.data)
            } else {
                self.data
            },
            id: self.id,
            listener_id: self.internal_id,
            protocol: self.protocol,
            hostname: self.hostname,
            tls_acceptor: self.tls.map(|config| TlsAcceptor::from(Arc::new(config))),
            is_tls_implicit: self.tls_implicit,
            limiter: ConcurrencyLimiter::new(manager.max_concurrent()),
            shutdown_rx,
        });

        // Spawn listeners
        for listener in self.listeners {
            tracing::info!(
                id = instance.id,
                protocol = ?instance.protocol,
                bind.ip = listener.addr.ip().to_string(),
                bind.port = listener.addr.port(),
                tls = instance.is_tls_implicit,
                "Starting listener"
            );
            let local_ip = listener.addr.ip();

            // Bind socket
            let listener = listener.listen();

            // Spawn listener
            let mut shutdown_rx = instance.shutdown_rx.clone();
            let manager = manager.clone();
            let instance = instance.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    // Enforce concurrency
                                    if let Some(in_flight) = instance.limiter.is_allowed() {
                                        let span = tracing::info_span!(
                                            "session",
                                            instance = instance.id,
                                            protocol = ?instance.protocol,
                                            remote.ip = remote_addr.ip().to_string(),
                                            remote.port = remote_addr.port(),
                                        );

                                        // Spawn connection
                                        manager.spawn(SessionData {
                                            stream,
                                            local_ip,
                                            remote_ip: remote_addr.ip(),
                                            span,
                                            in_flight,
                                            instance: instance.clone(),
                                        });
                                    } else {
                                        tracing::info!(
                                            context = "throttle",
                                            event = "too-many-requests",
                                            instance = instance.id,
                                            protocol = ?instance.protocol,
                                            remote.ip = remote_addr.ip().to_string(),
                                            remote.port = remote_addr.port(),
                                            max_concurrent = instance.limiter.max_concurrent,
                                            "Too many concurrent connections."
                                        );
                                    };
                                }
                                Err(err) => {
                                    tracing::debug!(context = "io",
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
                            break;
                        }
                    };
                }
            });
        }
    }
}

impl Servers {
    pub fn spawn(
        self,
        config: &Config,
        spawn: impl Fn(Server, watch::Receiver<bool>),
    ) -> watch::Sender<bool> {
        // Bind as root
        for server in &self.inner {
            for listener in &server.listeners {
                listener
                    .socket
                    .bind(listener.addr)
                    .failed(&format!("Failed to bind to {}", listener.addr));
            }
        }

        // Drop privileges
        #[cfg(not(target_env = "msvc"))]
        {
            if let Some(run_as_user) = config.value("server.run-as.user") {
                let mut pd = privdrop::PrivDrop::default().user(run_as_user);
                if let Some(run_as_group) = config.value("server.run-as.group") {
                    pd = pd.group(run_as_group);
                }
                pd.apply().failed("Failed to drop privileges");
            }
        }

        // Spawn listeners
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        for server in self.inner {
            spawn(server, shutdown_rx.clone());
        }

        shutdown_tx
    }
}

impl Listener {
    pub fn listen(self) -> TcpListener {
        let listener = self
            .socket
            .listen(self.backlog.unwrap_or(1024))
            .unwrap_or_else(|err| failed(&format!("Failed to listen on {}: {}", self.addr, err)));
        if let Some(ttl) = self.ttl {
            listener.set_ttl(ttl).unwrap_or_else(|err| {
                failed(&format!("Failed to set TTL on {}: {}", self.addr, err))
            });
        }
        listener
    }
}
