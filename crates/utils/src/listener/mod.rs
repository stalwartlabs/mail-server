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

use std::{net::IpAddr, sync::Arc};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use crate::config::ServerProtocol;

use self::limiter::{ConcurrencyLimiter, InFlight};

pub mod limiter;
pub mod listen;

pub struct ServerInstance {
    pub id: String,
    pub listener_id: u16,
    pub protocol: ServerProtocol,
    pub hostname: String,
    pub data: String,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub is_tls_implicit: bool,
    pub limiter: ConcurrencyLimiter,
    pub shutdown_rx: watch::Receiver<bool>,
}

pub struct SessionData<T: AsyncRead + AsyncWrite + Unpin + 'static> {
    pub stream: T,
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub span: tracing::Span,
    pub in_flight: InFlight,
    pub instance: Arc<ServerInstance>,
}

pub trait SessionManager: Sync + Send + 'static + Clone {
    fn spawn(&self, session: SessionData<TcpStream>);
    fn shutdown(&self);
}
