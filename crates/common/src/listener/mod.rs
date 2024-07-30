/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Instant};

use rustls::ServerConfig;
use std::fmt::Debug;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::{Accept, TlsAcceptor};
use utils::{config::ipmask::IpAddrMask, snowflake::SnowflakeIdGenerator};

use crate::{
    config::server::ServerProtocol,
    expr::{functions::ResolveVariable, *},
    Core,
};

use self::limiter::{ConcurrencyLimiter, InFlight};

pub mod acme;
pub mod blocked;
pub mod limiter;
pub mod listen;
pub mod stream;
pub mod tls;

pub struct ServerInstance {
    pub id: String,
    pub protocol: ServerProtocol,
    pub acceptor: TcpAcceptor,
    pub limiter: ConcurrencyLimiter,
    pub proxy_networks: Vec<IpAddrMask>,
    pub shutdown_rx: watch::Receiver<bool>,
    pub span_id_gen: Arc<SnowflakeIdGenerator>,
}

#[derive(Default)]
pub enum TcpAcceptor {
    Tls {
        config: Arc<ServerConfig>,
        acceptor: TlsAcceptor,
        implicit: bool,
    },
    #[default]
    Plain,
}

#[allow(clippy::large_enum_variant)]
pub enum TcpAcceptorResult<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    Tls(Accept<IO>),
    Plain(IO),
    Close,
}

pub struct SessionData<T: SessionStream> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: ServerProtocol,
    pub session_id: u64,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + 'static + Sync + Send {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResult {
    Continue,
    Close,
    UpgradeTls,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn<T: SessionStream>(
        &self,
        mut session: SessionData<T>,
        is_tls: bool,
        acme_core: Option<Arc<Core>>,
    ) {
        let manager = self.clone();

        tokio::spawn(async move {
            let start_time = Instant::now();
            let session_id;

            if is_tls {
                match session
                    .instance
                    .acceptor
                    .accept(session.stream, acme_core, &session.instance)
                    .await
                {
                    TcpAcceptorResult::Tls(accept) => match accept.await {
                        Ok(stream) => {
                            // Generate sessionId
                            session.session_id =
                                session.instance.span_id_gen.generate().unwrap_or_default();
                            session_id = session.session_id;

                            trc::event!(
                                Network(trc::NetworkEvent::ConnectionStart),
                                ListenerId = session.instance.id.clone(),
                                Protocol = session.instance.protocol,
                                RemoteIp = session.remote_ip,
                                RemotePort = session.remote_port,
                                SpanId = session.session_id,
                            );

                            manager
                                .handle(SessionData {
                                    stream,
                                    local_ip: session.local_ip,
                                    local_port: session.local_port,
                                    remote_ip: session.remote_ip,
                                    remote_port: session.remote_port,
                                    protocol: session.protocol,
                                    session_id: session.session_id,
                                    in_flight: session.in_flight,
                                    instance: session.instance,
                                })
                                .await;
                        }
                        Err(err) => {
                            trc::event!(
                                Tls(trc::TlsEvent::HandshakeError),
                                ListenerId = session.instance.id.clone(),
                                Protocol = session.instance.protocol,
                                RemoteIp = session.remote_ip,
                                RemotePort = session.remote_port,
                                Reason = err.to_string(),
                            );

                            return;
                        }
                    },
                    TcpAcceptorResult::Plain(stream) => {
                        // Generate sessionId
                        session.session_id =
                            session.instance.span_id_gen.generate().unwrap_or_default();
                        session_id = session.session_id;

                        trc::event!(
                            Network(trc::NetworkEvent::ConnectionStart),
                            ListenerId = session.instance.id.clone(),
                            Protocol = session.instance.protocol,
                            RemoteIp = session.remote_ip,
                            RemotePort = session.remote_port,
                            SpanId = session.session_id,
                        );

                        session.stream = stream;
                        manager.handle(session).await;
                    }
                    TcpAcceptorResult::Close => return,
                }
            } else {
                // Generate sessionId
                session.session_id = session.instance.span_id_gen.generate().unwrap_or_default();
                session_id = session.session_id;

                trc::event!(
                    Network(trc::NetworkEvent::ConnectionStart),
                    ListenerId = session.instance.id.clone(),
                    Protocol = session.instance.protocol,
                    RemoteIp = session.remote_ip,
                    RemotePort = session.remote_port,
                    SpanId = session.session_id,
                );

                manager.handle(session).await;
            }

            trc::event!(
                Network(trc::NetworkEvent::ConnectionEnd),
                SpanId = session_id,
                Elapsed = start_time.elapsed(),
            );
        });
    }

    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl<T: SessionStream> ResolveVariable for SessionData<T> {
    fn resolve_variable(&self, variable: u32) -> crate::expr::Variable<'_> {
        match variable {
            V_REMOTE_IP => self.remote_ip.to_string().into(),
            V_REMOTE_PORT => self.remote_port.into(),
            V_LOCAL_IP => self.local_ip.to_string().into(),
            V_LOCAL_PORT => self.local_port.into(),
            V_LISTENER => self.instance.id.as_str().into(),
            V_PROTOCOL => self.protocol.as_str().into(),
            V_TLS => self.stream.is_tls().into(),
            _ => crate::expr::Variable::default(),
        }
    }
}

impl Debug for TcpAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls {
                config, implicit, ..
            } => f
                .debug_struct("Tls")
                .field("config", config)
                .field("implicit", implicit)
                .finish(),
            Self::Plain => write!(f, "Plain"),
        }
    }
}
