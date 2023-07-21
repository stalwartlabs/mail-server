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

use std::time::Instant;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use utils::listener::SessionManager;

use crate::{
    core::{
        scripts::ScriptResult, Session, SessionData, SessionParameters, SmtpSessionManager, State,
    },
    queue, reporting,
};

use super::IsTls;

impl SessionManager for SmtpSessionManager {
    fn spawn(&self, session: utils::listener::SessionData<TcpStream>) {
        // Create session
        let mut session = Session {
            core: self.inner.clone(),
            instance: session.instance,
            state: State::default(),
            span: session.span,
            stream: session.stream,
            in_flight: vec![session.in_flight],
            data: SessionData::new(session.local_ip, session.remote_ip, session.remote_port),
            params: SessionParameters::default(),
        };

        tokio::spawn(async move {
            // Enforce throttle
            if session.is_allowed().await {
                if session.instance.is_tls_implicit {
                    if let Ok(mut session) = session.into_tls().await {
                        if session.init_conn().await {
                            session.handle_conn().await;
                        }
                    }
                } else if session.init_conn().await {
                    session.handle_conn().await;
                }
            }
        });
    }

    fn shutdown(&self) {
        // We spawn to avoid using async_trait
        let core = self.inner.clone();
        tokio::spawn(async move {
            let _ = core.queue.tx.send(queue::Event::Stop).await;
            let _ = core.report.tx.send(reporting::Event::Stop).await;
            #[cfg(feature = "local_delivery")]
            let _ = core.delivery_tx.send(utils::ipc::DeliveryEvent::Stop).await;
        });
    }
}

impl Session<TcpStream> {
    pub async fn into_tls(self) -> Result<Session<TlsStream<TcpStream>>, ()> {
        let span = self.span;
        Ok(Session {
            stream: self.instance.tls_accept(self.stream, &span).await?,
            state: self.state,
            data: self.data,
            instance: self.instance,
            core: self.core,
            in_flight: self.in_flight,
            params: self.params,
            span,
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

impl<T: AsyncRead + AsyncWrite + IsTls + Unpin> Session<T> {
    pub async fn init_conn(&mut self) -> bool {
        self.eval_session_params().await;
        self.verify_ip_dnsbl().await;

        // Sieve filtering
        if let Some(script) = self.core.session.config.connect.script.eval(self).await {
            if let ScriptResult::Reject(message) = self.run_script(script.clone(), None).await {
                tracing::debug!(parent: &self.span,
                        context = "connect",
                        event = "sieve-reject",
                        reason = message);

                let _ = self.write(message.as_bytes()).await;
                return false;
            }
        }

        let instance = self.instance.clone();
        if self.write(instance.data.as_bytes()).await.is_err() {
            return false;
        }

        true
    }

    pub async fn handle_conn_(&mut self) -> bool {
        let mut buf = vec![0; 8192];
        let mut shutdown_rx = self.instance.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    self.params.timeout,
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    if Instant::now() < self.data.valid_until && bytes_read <= self.data.bytes_left  {
                                        self.data.bytes_left -= bytes_read;
                                        match self.ingest(&buf[..bytes_read]).await {
                                            Ok(true) => (),
                                            Ok(false) => {
                                                return true;
                                            }
                                            Err(_) => {
                                                break;
                                            }
                                        }
                                    } else if bytes_read > self.data.bytes_left {
                                        self
                                            .write(format!("451 4.7.28 {} Session exceeded transfer quota.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "transfer-limit",
                                            "Client exceeded incoming transfer limit."
                                        );
                                        break;
                                    } else {
                                        self
                                            .write(format!("453 4.3.2 {} Session open for too long.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "loiter",
                                            "Session open for too long."
                                        );
                                        break;
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
                                    .write(format!("221 2.0.0 {} Disconnecting inactive client.\r\n", self.instance.hostname).as_bytes())
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
                    self.write(b"421 4.3.0 Server shutting down.\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }
}
