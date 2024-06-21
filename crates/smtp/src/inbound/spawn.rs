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

use common::{
    config::smtp::session::Stage,
    listener::{self, SessionManager, SessionStream},
};
use tokio_rustls::server::TlsStream;

use crate::{
    core::{Session, SessionData, SessionParameters, SmtpSessionManager, State},
    queue, reporting,
    scripts::ScriptResult,
};

impl SessionManager for SmtpSessionManager {
    fn handle<T: SessionStream>(
        self,
        session: listener::SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        // Create session
        let mut session = Session {
            hostname: String::new(),
            core: self.inner.into(),
            instance: session.instance,
            state: State::default(),
            span: session.span,
            stream: session.stream,
            in_flight: vec![session.in_flight],
            data: SessionData::new(
                session.local_ip,
                session.local_port,
                session.remote_ip,
                session.remote_port,
            ),
            params: SessionParameters::default(),
        };

        // Enforce throttle
        async {
            if session.is_allowed().await
                && session.init_conn().await
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
        async {
            let _ = self.inner.inner.queue_tx.send(queue::Event::Stop).await;
            let _ = self
                .inner
                .inner
                .report_tx
                .send(reporting::Event::Stop)
                .await;
            let _ = self
                .inner
                .inner
                .ipc
                .delivery_tx
                .send(common::DeliveryEvent::Stop)
                .await;
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn init_conn(&mut self) -> bool {
        self.eval_session_params().await;

        let config = &self.core.core.smtp.session.connect;

        // Sieve filtering
        if let Some(script) = self
            .core
            .core
            .eval_if::<String, _>(&config.script, self)
            .await
            .and_then(|name| self.core.core.get_sieve_script(&name))
        {
            if let ScriptResult::Reject(message) = self
                .run_script(script.clone(), self.build_script_parameters("connect"))
                .await
            {
                tracing::debug!(parent: &self.span,
                        context = "connect",
                        event = "sieve-reject",
                        reason = message);

                let _ = self.write(message.as_bytes()).await;
                return false;
            }
        }

        // Milter filtering
        if let Err(message) = self.run_milters(Stage::Connect, None).await {
            tracing::debug!(parent: &self.span,
                context = "connect",
                event = "milter-reject",
                reason = message.message.as_ref());
            let _ = self.write(message.message.as_bytes()).await;
            return false;
        }

        // FilterHook filtering
        if let Err(message) = self.run_filter_hooks(Stage::Connect, None).await {
            tracing::debug!(parent: &self.span,
                context = "connect",
                event = "filter_hook-reject",
                reason = message.message.as_ref());
            let _ = self.write(message.message.as_bytes()).await;
            return false;
        }

        // Obtain hostname
        self.hostname = self
            .core
            .core
            .eval_if::<String, _>(&config.hostname, self)
            .await
            .unwrap_or_default();
        if self.hostname.is_empty() {
            tracing::warn!(parent: &self.span,
                context = "connect",
                event = "hostname",
                "No hostname configured, using 'localhost'."
            );
            self.hostname = "localhost".to_string();
        }

        // Obtain greeting
        let greeting = self
            .core
            .core
            .eval_if::<String, _>(&config.greeting, self)
            .await
            .filter(|g| !g.is_empty())
            .map(|g| format!("220 {}\r\n", g))
            .unwrap_or_else(|| "220 Stalwart ESMTP at your service.\r\n".to_string());

        if self.write(greeting.as_bytes()).await.is_err() {
            return false;
        }

        true
    }

    pub async fn handle_conn(&mut self) -> bool {
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
                                            .write(format!("451 4.7.28 {} Session exceeded transfer quota.\r\n", self.hostname).as_bytes())
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
                                            .write(format!("453 4.3.2 {} Session open for too long.\r\n", self.hostname).as_bytes())
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
                                    .write(format!("221 2.0.0 {} Disconnecting inactive client.\r\n", self.hostname).as_bytes())
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

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        let span = self.span;
        Ok(Session {
            hostname: self.hostname,
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
}
