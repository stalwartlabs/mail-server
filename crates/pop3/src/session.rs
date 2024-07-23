/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use common::listener::{SessionData, SessionManager, SessionResult, SessionStream};
use jmap::JMAP;
use tokio_rustls::server::TlsStream;

use crate::{
    protocol::{
        request::Parser,
        response::{Response, SerializeResponse},
    },
    Pop3SessionManager, Session, State, SERVER_GREETING,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl SessionManager for Pop3SessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let mut session = Session {
                jmap: JMAP::from(self.pop3.jmap_instance),
                imap: self.pop3.imap_inner,
                instance: session.instance,
                receiver: Parser::default(),
                state: State::NotAuthenticated {
                    auth_failures: 0,
                    username: None,
                },
                stream: session.stream,
                in_flight: session.in_flight,
                remote_addr: session.remote_ip,
                session_id: session.session_id,
            };

            if session
                .write_bytes(SERVER_GREETING.as_bytes())
                .await
                .is_ok()
                && session.handle_conn().await
                && session.instance.acceptor.is_tls()
            {
                if let Ok(mut session) = session.into_tls().await {
                    session.handle_conn().await;
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
                    self.stream.read(&mut buf)) => {
                    match result {
                        Ok(Ok(bytes_read)) => {
                            if bytes_read > 0 {
                                match self.ingest(&buf[..bytes_read]).await {
                                    SessionResult::Continue => (),
                                    SessionResult::UpgradeTls => {
                                        return true;
                                    }
                                    SessionResult::Close => {
                                        tracing::debug!( event = "disconnect", "Disconnecting client.");
                                        break;
                                    }
                                }
                            } else {
                                tracing::debug!( event = "close", "POP3 connection closed by client.");
                                break;
                            }
                        },
                        Ok(Err(err)) => {
                            tracing::debug!( event = "error", reason = %err, "POP3 connection error.");
                            break;
                        },
                        Err(_) => {
                            self.write_bytes(&b"-ERR Connection timed out.\r\n"[..]).await.ok();
                            tracing::debug!( "POP3 connection timed out.");
                            break;
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
                    tracing::debug!( event = "shutdown", "POP3 server shutting down.");
                    break;
                }
            };
        }

        false
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        Ok(Session {
            stream: self
                .instance
                .tls_accept(self.stream, self.session_id)
                .await?,
            jmap: self.jmap,
            imap: self.imap,
            instance: self.instance,
            receiver: self.receiver,
            state: self.state,
            session_id: self.session_id,
            in_flight: self.in_flight,
            remote_addr: self.remote_addr,
        })
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn write_bytes(&mut self, bytes: impl AsRef<[u8]>) -> trc::Result<()> {
        let bytes = bytes.as_ref();
        /*for line in String::from_utf8_lossy(bytes.as_ref()).split("\r\n") {
            let c = println!("{}", line);
        }*/
        tracing::trace!(
            event = "write",
            data = std::str::from_utf8(bytes).unwrap_or_default(),
            size = bytes.len()
        );

        self.stream.write_all(bytes.as_ref()).await.map_err(|err| {
            trc::NetworkEvent::WriteError
                .into_err()
                .reason(err)
                .caused_by(trc::location!())
        })?;
        self.stream.flush().await.map_err(|err| {
            trc::NetworkEvent::WriteError
                .into_err()
                .reason(err)
                .caused_by(trc::location!())
        })
    }

    pub async fn write_ok(&mut self, message: impl Into<Cow<'static, str>>) -> trc::Result<()> {
        self.write_bytes(Response::Ok::<u32>(message.into()).serialize())
            .await
    }

    pub async fn write_err(&mut self, err: trc::Error) -> bool {
        tracing::error!("POP3 error: {}", err);
        let disconnect = err.must_disconnect();

        if err.should_write_err() {
            if let Err(err) = self.write_bytes(err.serialize()).await {
                tracing::debug!("Failed to write error: {}", err);
                return false;
            }
        }

        !disconnect
    }
}
