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
                                trc::event!(
                                    Network(trc::NetworkEvent::Closed),
                                    SpanId = self.session_id,
                                    CausedBy = trc::location!()
                                );
                                break;
                            }
                        },
                        Ok(Err(err)) => {
                            trc::event!(
                                Network(trc::NetworkEvent::ReadError),
                                SpanId = self.session_id,
                                Reason = err.to_string(),
                                CausedBy = trc::location!()
                            );
                            break;
                        },
                        Err(_) => {
                            trc::event!(
                                Network(trc::NetworkEvent::Timeout),
                                SpanId = self.session_id,
                                CausedBy = trc::location!()
                            );
                            self.write_bytes(&b"* BYE Connection timed out.\r\n"[..]).await.ok();
                            break;
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    trc::event!(
                        Network(trc::NetworkEvent::Closed),
                        SpanId = self.session_id,
                        Reason = "Server shutting down",
                        CausedBy = trc::location!()
                    );
                    self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
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
            trc::event!(
                Network(trc::NetworkEvent::WriteError),
                Reason = err.to_string(),
                SpanId = session.session_id,
                Details = "Failed to write to stream"
            );
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
            trc::event!(
                Network(trc::NetworkEvent::SplitError),
                SpanId = self.session_id,
                Details = "Failed to obtain write half state"
            );
            return Err(());
        };

        // Take ownership of WriteHalf and unsplit it from ReadHalf
        let stream = if let Ok(stream_tx) =
            Arc::try_unwrap(self.stream_tx).map(|mutex| mutex.into_inner())
        {
            self.stream_rx.unsplit(stream_tx)
        } else {
            trc::event!(
                Network(trc::NetworkEvent::SplitError),
                SpanId = self.session_id,
                Details = "Failed to take ownership of write half"
            );

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

        trc::event!(
            Imap(trc::ImapEvent::RawOutput),
            SpanId = self.session_id,
            Size = bytes.len(),
            Contents = trc::Value::from_maybe_string(bytes),
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
        if err.should_write_err() {
            let disconnect = err.must_disconnect();
            let bytes = err.serialize();
            trc::error!(err.span_id(self.session_id));

            if let Err(err) = self.write_bytes(bytes).await {
                trc::error!(err.span_id(self.session_id));
                false
            } else {
                !disconnect
            }
        } else {
            trc::error!(err);

            false
        }
    }
}

impl<T: SessionStream> super::SessionData<T> {
    pub async fn write_bytes(&self, bytes: impl AsRef<[u8]>) -> trc::Result<()> {
        let bytes = bytes.as_ref();

        trc::event!(
            Imap(trc::ImapEvent::RawOutput),
            SpanId = self.session_id,
            Size = bytes.len(),
            Contents = trc::Value::from_maybe_string(bytes),
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
        if err.should_write_err() {
            let bytes = err.serialize();
            trc::error!(err.span_id(self.session_id));
            self.write_bytes(bytes).await
        } else {
            trc::error!(err.span_id(self.session_id));
            Ok(())
        }
    }
}
