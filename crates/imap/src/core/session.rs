/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::listener::{stream::NullIo, SessionData, SessionManager, SessionResult, SessionStream};
use imap_proto::{
    protocol::{ProtocolVersion, SerializeResponse},
    receiver::Receiver,
};
use jmap::JMAP;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::server::TlsStream;

use super::{ImapSessionManager, Session, State};

impl SessionManager for ImapSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            if let Ok(mut session) = Session::new(session, self).await {
                if session.handle_conn().await && session.instance.acceptor.is_tls() {
                    if let Ok(mut session) = session.into_tls().await {
                        session.handle_conn().await;
                    }
                }
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_conn(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    if !matches!(self.state, State::NotAuthenticated {..}) {
                        self.jmap.core.imap.timeout_auth
                    } else {
                        self.jmap.core.imap.timeout_unauth
                    },
                    self.stream_rx.read(&mut buf)) => {
                    match result {
                        Ok(Ok(bytes_read)) => {
                            if bytes_read > 0 {
                                match self.ingest(&buf[..bytes_read]).await {
                                    SessionResult::Continue => (),
                                    SessionResult::UpgradeTls => {
                                        return true;
                                    }
                                    SessionResult::Close => {
                                        break;
                                    }
                                }
                            } else {
                                tracing::debug!( event = "close", "IMAP connection closed by client.");
                                break;
                            }
                        },
                        Ok(Err(err)) => {
                            tracing::debug!( event = "error", reason = %err, "IMAP connection error.");
                            break;
                        },
                        Err(_) => {
                            self.write_bytes(&b"* BYE Connection timed out.\r\n"[..]).await.ok();
                            tracing::debug!( "IMAP connection timed out.");
                            break;
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
                    tracing::debug!( event = "shutdown", "IMAP server shutting down.");
                    break;
                }
            };
        }

        false
    }

    pub async fn new(
        mut session: SessionData<T>,
        manager: ImapSessionManager,
    ) -> Result<Session<T>, ()> {
        // Write greeting
        let (is_tls, greeting) = if session.stream.is_tls() {
            (true, &manager.imap.imap_inner.greeting_tls)
        } else {
            (false, &manager.imap.imap_inner.greeting_plain)
        };
        if let Err(err) = session.stream.write_all(greeting).await {
            tracing::debug!( event = "error", reason = %err, "Failed to write greeting.");
            return Err(());
        }
        let _ = session.stream.flush().await;

        // Split stream into read and write halves
        let (stream_rx, stream_tx) = tokio::io::split(session.stream);
        let jmap = JMAP::from(manager.imap.jmap_instance);

        Ok(Session {
            receiver: Receiver::with_max_request_size(jmap.core.imap.max_request_size),
            version: ProtocolVersion::Rev1,
            state: State::NotAuthenticated { auth_failures: 0 },
            is_tls,
            is_condstore: false,
            is_qresync: false,
            jmap,
            imap: manager.imap.imap_inner,
            instance: session.instance,
            session_id: session.session_id,
            in_flight: session.in_flight,
            remote_addr: session.remote_ip,
            stream_rx,
            stream_tx: Arc::new(tokio::sync::Mutex::new(stream_tx)),
        })
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        // Drop references to write half from state
        let state = if let Some(state) =
            self.state
                .try_replace_stream_tx(Arc::new(tokio::sync::Mutex::new(
                    tokio::io::split(NullIo::default()).1,
                ))) {
            state
        } else {
            tracing::debug!("Failed to obtain write half state.");
            return Err(());
        };

        // Take ownership of WriteHalf and unsplit it from ReadHalf
        let stream = if let Ok(stream_tx) =
            Arc::try_unwrap(self.stream_tx).map(|mutex| mutex.into_inner())
        {
            self.stream_rx.unsplit(stream_tx)
        } else {
            tracing::debug!("Failed to take ownership of write half.");
            return Err(());
        };

        // Upgrade to TLS
        let (stream_rx, stream_tx) =
            tokio::io::split(self.instance.tls_accept(stream, self.session_id).await?);
        let stream_tx = Arc::new(tokio::sync::Mutex::new(stream_tx));

        Ok(Session {
            jmap: self.jmap,
            imap: self.imap,
            instance: self.instance,
            receiver: self.receiver,
            version: self.version,
            state: state.try_replace_stream_tx(stream_tx.clone()).unwrap(),
            is_tls: true,
            is_condstore: self.is_condstore,
            is_qresync: self.is_qresync,
            session_id: self.session_id,
            in_flight: self.in_flight,
            remote_addr: self.remote_addr,
            stream_rx,
            stream_tx,
        })
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn write_bytes(&self, bytes: impl AsRef<[u8]>) -> trc::Result<()> {
        let bytes = bytes.as_ref();
        /*for line in String::from_utf8_lossy(bytes.as_ref()).split("\r\n") {
            let c = println!("{}", line);
        }*/
        tracing::trace!(
            event = "write",
            data = std::str::from_utf8(bytes).unwrap_or_default(),
            size = bytes.len()
        );

        let mut stream = self.stream_tx.lock().await;
        if let Err(err) = stream.write_all(bytes).await {
            Err(trc::NetworkEvent::WriteError
                .into_err()
                .reason(err)
                .details("Failed to write to stream"))
        } else {
            let _ = stream.flush().await;
            Ok(())
        }
    }

    pub async fn write_error(&self, err: trc::Error) -> bool {
        tracing::warn!( event = "error", reason = %err, "IMAP error.");

        if err.should_write_err() {
            let disconnect = err.must_disconnect();

            if let Err(err) = self.write_bytes(err.serialize()).await {
                tracing::debug!( event = "error", reason = %err, "Failed to write error.");
                false
            } else {
                !disconnect
            }
        } else {
            false
        }
    }
}

impl<T: SessionStream> super::SessionData<T> {
    pub async fn write_bytes(&self, bytes: impl AsRef<[u8]>) -> trc::Result<()> {
        let bytes = bytes.as_ref();
        /*for line in String::from_utf8_lossy(bytes.as_ref()).split("\r\n") {
            let c = println!("{}", line);
        }*/
        tracing::trace!(
            event = "write",
            data = std::str::from_utf8(bytes).unwrap_or_default(),
            size = bytes.len()
        );

        let mut stream = self.stream_tx.lock().await;
        if let Err(err) = stream.write_all(bytes.as_ref()).await {
            Err(trc::NetworkEvent::WriteError
                .into_err()
                .reason(err)
                .details("Failed to write to stream"))
        } else {
            let _ = stream.flush().await;
            Ok(())
        }
    }

    pub async fn write_error(&self, err: trc::Error) -> trc::Result<()> {
        tracing::warn!( event = "error", reason = %err, "IMAP error.");

        if err.should_write_err() {
            self.write_bytes(err.serialize()).await
        } else {
            Ok(())
        }
    }
}
