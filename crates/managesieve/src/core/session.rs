use imap_proto::receiver::{self, Receiver};
use jmap::auth::rate_limit::RemoteAddress;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use utils::listener::SessionManager;

use crate::SERVER_GREETING;

use super::{IsTls, ManageSieveSessionManager, Session, State};

impl SessionManager for ManageSieveSessionManager {
    fn spawn(&self, session: utils::listener::SessionData<TcpStream>) {
        // Create session
        let mut session = Session {
            jmap: self.jmap.clone(),
            imap: self.imap.clone(),
            instance: session.instance,
            state: State::NotAuthenticated { auth_failures: 0 },
            span: session.span,
            stream: session.stream,
            in_flight: session.in_flight,
            remote_addr: RemoteAddress::IpAddress(session.remote_ip),
            receiver: Receiver::with_max_request_size(self.imap.max_request_size)
                .with_start_state(receiver::State::Command { is_uid: false }),
        };

        tokio::spawn(async move {
            if session.instance.is_tls_implicit {
                if let Ok(mut session) = session.into_tls().await {
                    if session
                        .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                        .await
                        .is_ok()
                    {
                        session.handle_conn().await;
                    }
                }
            } else if session
                .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                .await
                .is_ok()
            {
                session.handle_conn().await;
            }
        });
    }

    fn shutdown(&self) {
        // No-op
    }
}

impl<T: AsyncRead + AsyncWrite + IsTls + Unpin> Session<T> {
    pub async fn handle_conn_(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    if !matches!(self.state, State::NotAuthenticated {..}) {
                        self.imap.timeout_auth
                    } else {
                        self.imap.timeout_unauth
                    },
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    match self.ingest(&buf[..bytes_read]).await {
                                        Ok(true) => (),
                                        Ok(false) => {
                                            return true;
                                        }
                                        Err(_) => {
                                            break;
                                        }
                                    }
                                } else {
                                    tracing::debug!(
                                        parent: &self.span,
                                        event = "disconnect",
                                        reason = "peer",
                                        "Connection closed by peer."
                                    );
                                    break;
                                }
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    parent: &self.span,
                                    event = "disconnect",
                                    reason = "timeout",
                                    "Connection timed out."
                                );
                                self
                                    .write(b"BYE \"Connection timed out.\"\r\n")
                                    .await
                                    .ok();
                                break;
                            }
                        }
                },
                _ = shutdown_rx.changed() => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        reason = "shutdown",
                        "Server shutting down."
                    );
                    self.write(b"BYE \"Server shutting down.\"\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }
}

impl Session<TcpStream> {
    pub async fn into_tls(self) -> Result<Session<TlsStream<TcpStream>>, ()> {
        let span = self.span;
        Ok(Session {
            stream: self.instance.tls_accept(self.stream, &span).await?,
            state: self.state,
            instance: self.instance,
            in_flight: self.in_flight,
            span,
            jmap: self.jmap,
            imap: self.imap,
            receiver: self.receiver,
            remote_addr: self.remote_addr,
        })
    }

    pub async fn handle_conn(mut self) {
        if self.handle_conn_().await && self.instance.tls_acceptor.is_some() {
            if let Ok(session) = self.into_tls().await {
                session.handle_conn().await;
            }
        }
    }
}

impl Session<TlsStream<TcpStream>> {
    pub async fn handle_conn(mut self) {
        self.handle_conn_().await;
    }
}
