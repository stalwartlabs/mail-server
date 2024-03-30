/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::{borrow::Cow, net::IpAddr, sync::Arc};

use rustls::ServerConfig;
use std::fmt::Debug;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};
use tokio_rustls::{Accept, TlsAcceptor};
use utils::config::ipmask::IpAddrMask;

use crate::{
    config::server::ServerProtocol,
    expr::{functions::ResolveVariable, *},
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
}

#[derive(Default)]
pub enum TcpAcceptor {
    Tls {
        acme_config: Arc<ServerConfig>,
        default_config: Arc<ServerConfig>,
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
    pub span: tracing::Span,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + 'static + Sync + Send {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn<T: SessionStream>(
        &self,
        mut session: SessionData<T>,
        is_tls: bool,
        enable_acme: bool,
    ) {
        let manager = self.clone();

        tokio::spawn(async move {
            if is_tls {
                match session
                    .instance
                    .acceptor
                    .accept(session.stream, enable_acme)
                    .await
                {
                    TcpAcceptorResult::Tls(accept) => match accept.await {
                        Ok(stream) => {
                            let session = SessionData {
                                stream,
                                local_ip: session.local_ip,
                                local_port: session.local_port,
                                remote_ip: session.remote_ip,
                                remote_port: session.remote_port,
                                protocol: session.protocol,
                                span: session.span,
                                in_flight: session.in_flight,
                                instance: session.instance,
                            };
                            manager.handle(session).await;
                        }
                        Err(err) => {
                            tracing::debug!(
                                context = "tls",
                                event = "error",
                                instance = session.instance.id,
                                protocol = ?session.instance.protocol,
                                remote.ip = session.remote_ip.to_string(),
                                "Failed to accept TLS connection: {}",
                                err
                            );
                        }
                    },
                    TcpAcceptorResult::Plain(stream) => {
                        session.stream = stream;
                        manager.handle(session).await;
                    }
                    TcpAcceptorResult::Close => (),
                }
            } else {
                manager.handle(session).await;
            }
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
                acme_config,
                default_config,
                implicit,
                ..
            } => f
                .debug_struct("Tls")
                .field("acme_config", acme_config)
                .field("default_config", default_config)
                .field("implicit", implicit)
                .finish(),
            Self::Plain => write!(f, "Plain"),
        }
    }
}
