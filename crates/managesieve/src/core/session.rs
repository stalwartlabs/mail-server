/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::{SessionData, SessionManager, SessionResult, SessionStream};
use imap_proto::receiver::{self, Receiver};
use jmap::JMAP;
use tokio_rustls::server::TlsStream;

use crate::SERVER_GREETING;

use super::{ManageSieveSessionManager, Session, State};

impl SessionManager for ManageSieveSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            // Create session
            let jmap = JMAP::from(self.imap.jmap_instance);
            let mut session = Session {
                receiver: Receiver::with_max_request_size(jmap.core.imap.max_request_size)
                    .with_start_state(receiver::State::Command { is_uid: false }),
                jmap,
                imap: self.imap.imap_inner,
                instance: session.instance,
                state: State::NotAuthenticated { auth_failures: 0 },
                session_id: session.session_id,
                stream: session.stream,
                in_flight: session.in_flight,
                remote_addr: session.remote_ip,
            };

            if session
                .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                .await
                .is_ok()
                && session.handle_conn().await
                && session.instance.acceptor.is_tls()
            {
                if let Ok(mut session) = session.into_tls().await {
                    let _ = session
                        .write(&session.handle_capability(SERVER_GREETING).await.unwrap())
                        .await;
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
                    self.read(&mut buf)) => {
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
                                        SessionId = self.session_id,
                                        CausedBy = trc::location!()
                                    );
                                    break;
                                }
                            }
                            Ok(Err(err)) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::ReadError),
                                    SessionId = self.session_id,
                                    Reason = err,
                                    CausedBy = trc::location!()
                                );
                                break;
                            }
                            Err(_) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::Timeout),
                                    SessionId = self.session_id,
                                    CausedBy = trc::location!()
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
                    trc::event!(
                        Network(trc::NetworkEvent::Closed),
                        SessionId = self.session_id,
                        Reason = "Server shutting down",
                        CausedBy = trc::location!()
                    );
                    self.write(b"BYE \"Server shutting down.\"\r\n").await.ok();
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
            state: self.state,
            instance: self.instance,
            in_flight: self.in_flight,
            session_id: self.session_id,
            jmap: self.jmap,
            imap: self.imap,
            receiver: self.receiver,
            remote_addr: self.remote_addr,
        })
    }
}
