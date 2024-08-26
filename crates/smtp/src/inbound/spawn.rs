/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::{
    config::smtp::session::Stage,
    listener::{self, SessionManager, SessionStream},
};
use tokio_rustls::server::TlsStream;
use trc::SmtpEvent;

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
            stream: session.stream,
            in_flight: vec![session.in_flight],
            data: SessionData::new(
                session.local_ip,
                session.local_port,
                session.remote_ip,
                session.remote_port,
                session.session_id,
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
        if let Some((script, script_id)) = self
            .core
            .core
            .eval_if::<String, _>(&config.script, self, self.data.session_id)
            .await
            .and_then(|name| {
                self.core
                    .core
                    .get_sieve_script(&name, self.data.session_id)
                    .map(|s| (s, name))
            })
        {
            if let ScriptResult::Reject(message) = self
                .run_script(
                    script_id,
                    script.clone(),
                    self.build_script_parameters("connect"),
                )
                .await
            {
                let _ = self.write(message.as_bytes()).await;
                return false;
            }
        }

        // Milter filtering
        if let Err(message) = self.run_milters(Stage::Connect, None).await {
            let _ = self.write(message.message.as_bytes()).await;
            return false;
        }

        // MTAHook filtering
        if let Err(message) = self.run_mta_hooks(Stage::Connect, None, None).await {
            let _ = self.write(message.message.as_bytes()).await;
            return false;
        }

        // Obtain hostname
        self.hostname = self
            .core
            .core
            .eval_if::<String, _>(&config.hostname, self, self.data.session_id)
            .await
            .unwrap_or_default();
        if self.hostname.is_empty() {
            trc::event!(
                Smtp(SmtpEvent::MissingLocalHostname),
                SpanId = self.data.session_id,
            );
            self.hostname = "localhost".to_string();
        }

        // Obtain greeting
        let greeting = self
            .core
            .core
            .eval_if::<String, _>(&config.greeting, self, self.data.session_id)
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

                                        trc::event!(
                                            Smtp(SmtpEvent::TransferLimitExceeded),
                                            SpanId = self.data.session_id,
                                        );

                                        break;
                                    } else {
                                        self
                                            .write(format!("453 4.3.2 {} Session open for too long.\r\n", self.hostname).as_bytes())
                                            .await
                                            .ok();

                                        trc::event!(
                                            Smtp(SmtpEvent::TimeLimitExceeded),
                                            SpanId = self.data.session_id,
                                        );

                                        break;
                                    }
                                } else {
                                    trc::event!(
                                        Network(trc::NetworkEvent::Closed),
                                        SpanId = self.data.session_id,
                                        CausedBy = trc::location!()
                                    );

                                    break;
                                }
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_) => {
                                trc::event!(
                                    Network(trc::NetworkEvent::Timeout),
                                    SpanId = self.data.session_id,
                                    CausedBy = trc::location!()
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
                    trc::event!(
                        Network(trc::NetworkEvent::Closed),
                        SpanId = self.data.session_id,
                        Reason = "Server shutting down",
                        CausedBy = trc::location!()
                    );
                    self.write(b"421 4.3.0 Server shutting down.\r\n").await.ok();
                    break;
                }
            };
        }

        false
    }

    pub async fn into_tls(self) -> Result<Session<TlsStream<T>>, ()> {
        Ok(Session {
            hostname: self.hostname,
            stream: self
                .instance
                .tls_accept(self.stream, self.data.session_id)
                .await?,
            state: self.state,
            data: self.data,
            instance: self.instance,
            core: self.core,
            in_flight: self.in_flight,
            params: self.params,
        })
    }
}
