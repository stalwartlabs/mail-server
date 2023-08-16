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

use imap_proto::{protocol::ProtocolVersion, receiver::Receiver};
use jmap::auth::rate_limit::RemoteAddress;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};
use tokio_rustls::server::TlsStream;
use utils::listener::{SessionData, SessionManager};

use super::{writer, ImapSessionManager, Session, State};

impl SessionManager for ImapSessionManager {
    fn spawn(&self, session: SessionData<TcpStream>) {
        let manager = self.clone();

        tokio::spawn(async move {
            if session.instance.is_tls_implicit {
                if let Ok(session) = Session::<TlsStream<TcpStream>>::new(session, manager).await {
                    session.handle_conn().await;
                }
            } else if let Ok(session) = Session::<TcpStream>::new(session, manager).await {
                session.handle_conn().await;
            }
        });
    }

    fn shutdown(&self) {
        // No-op
    }
}

impl<T: AsyncRead> Session<T> {
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
                    self.stream_rx.read(&mut buf)) => {
                    match result {
                        Ok(Ok(bytes_read)) => {
                            if bytes_read > 0 {
                                match self.ingest(&buf[..bytes_read]).await {
                                    Ok(false) => (),
                                    Ok(true) => {
                                        return true;
                                    }
                                    Err(_) => {
                                        tracing::debug!(parent: &self.span, event = "disconnect", "Disconnecting client.");
                                        break;
                                    }
                                }
                            } else {
                                tracing::debug!(parent: &self.span, event = "close", "IMAP connection closed by client.");
                                break;
                            }
                        },
                        Ok(Err(err)) => {
                            tracing::debug!(parent: &self.span, event = "error", reason = %err, "IMAP connection error.");
                            break;
                        },
                        Err(_) => {
                            self.write_bytes(&b"* BYE Connection timed out.\r\n"[..]).await.ok();
                            tracing::debug!(parent: &self.span, "IMAP connection timed out.");
                            break;
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
                    tracing::debug!(parent: &self.span, event = "shutdown", "IMAP server shutting down.");
                    break;
                }
            };
        }

        false
    }
}

impl Session<TcpStream> {
    pub async fn new(
        mut session: SessionData<TcpStream>,
        manager: ImapSessionManager,
    ) -> Result<Session<TcpStream>, ()> {
        // Write plain text greeting
        if let Err(err) = session.stream.write_all(&manager.imap.greeting_plain).await {
            tracing::debug!(parent: &session.span, event = "error", reason = %err, "Failed to write greeting.");
            return Err(());
        }
        let _ = session.stream.flush().await;

        // Split stream into read and write halves
        let (stream_rx, stream_tx) = tokio::io::split(session.stream);

        Ok(Session {
            receiver: Receiver::with_max_request_size(manager.imap.max_request_size),
            version: ProtocolVersion::Rev1,
            state: State::NotAuthenticated { auth_failures: 0 },
            writer: writer::spawn_writer(writer::Event::Stream(stream_tx), session.span.clone()),
            is_tls: false,
            is_condstore: false,
            is_qresync: false,
            imap: manager.imap,
            jmap: manager.jmap,
            instance: session.instance,
            span: session.span,
            in_flight: session.in_flight,
            remote_addr: RemoteAddress::IpAddress(session.remote_ip),
            stream_rx,
        })
    }

    pub async fn handle_conn(mut self) {
        if self.handle_conn_().await && self.instance.tls_acceptor.is_some() {
            if let Ok(session) = self.into_tls().await {
                session.handle_conn().await;
            }
        }
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<TcpStream>>, ()> {
        // Recover WriteHalf from writer
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self.writer.send(writer::Event::Upgrade(tx)).await {
            tracing::debug!("Failed to write to channel: {}", err);
            return Err(());
        }
        let stream = if let Ok(stream_tx) = rx.await {
            self.stream_rx.unsplit(stream_tx)
        } else {
            tracing::debug!("Failed to read from channel");
            return Err(());
        };

        // Upgrade to TLS
        let (stream_rx, stream_tx) =
            tokio::io::split(self.instance.tls_accept(stream, &self.span).await?);
        if let Err(err) = self.writer.send(writer::Event::StreamTls(stream_tx)).await {
            tracing::debug!("Failed to send stream: {}", err);
            return Err(());
        }

        Ok(Session {
            jmap: self.jmap,
            imap: self.imap,
            instance: self.instance,
            receiver: self.receiver,
            version: self.version,
            state: self.state,
            is_tls: true,
            is_condstore: self.is_condstore,
            is_qresync: self.is_qresync,
            writer: self.writer,
            span: self.span,
            in_flight: self.in_flight,
            remote_addr: self.remote_addr,
            stream_rx,
        })
    }
}

impl Session<TlsStream<TcpStream>> {
    pub async fn new(
        session: utils::listener::SessionData<TcpStream>,
        manager: ImapSessionManager,
    ) -> Result<Session<TlsStream<TcpStream>>, ()> {
        // Upgrade to TLS
        let mut stream = session
            .instance
            .tls_accept(session.stream, &session.span)
            .await?;

        // Write TLS greeting
        let span = session.span;
        if let Err(err) = stream.write_all(&manager.imap.greeting_tls).await {
            tracing::debug!(parent: &span, event = "error", reason = %err, "Failed to write greeting.");
            return Err(());
        }
        let _ = stream.flush().await;

        // Spit stream into read and write halves
        let (stream_rx, stream_tx) = tokio::io::split(stream);

        Ok(Session {
            receiver: Receiver::with_max_request_size(manager.imap.max_request_size),
            version: ProtocolVersion::Rev1,
            state: State::NotAuthenticated { auth_failures: 0 },
            writer: writer::spawn_writer(writer::Event::StreamTls(stream_tx), span.clone()),
            is_tls: true,
            is_condstore: false,
            is_qresync: false,
            imap: manager.imap,
            jmap: manager.jmap,
            instance: session.instance,
            span,
            in_flight: session.in_flight,
            remote_addr: RemoteAddress::IpAddress(session.remote_ip),
            stream_rx,
        })
    }

    pub async fn handle_conn(mut self) {
        self.handle_conn_().await;
    }
}
