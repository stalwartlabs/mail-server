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

pub mod client;
pub mod config;
pub mod lookup;
pub mod pool;
pub mod tls;

use std::{fmt::Display, sync::atomic::AtomicU64, time::Duration};

use bb8::Pool;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::LookupList;

pub struct ImapDirectory {
    pool: Pool<ImapConnectionManager>,
    domains: LookupList,
}

pub struct ImapConnectionManager {
    addr: String,
    timeout: Duration,
    tls_connector: TlsConnector,
    tls_hostname: String,
    tls_implicit: bool,
    mechanisms: AtomicU64,
}

pub struct ImapClient<T: AsyncRead + AsyncWrite> {
    stream: T,
    mechanisms: u64,
    is_valid: bool,
    timeout: Duration,
}

#[derive(Debug)]
pub enum ImapError {
    Io(std::io::Error),
    Timeout,
    InvalidResponse(String),
    InvalidChallenge(String),
    AuthenticationFailed,
    TLSInvalidName,
    Disconnected,
}

impl From<std::io::Error> for ImapError {
    fn from(error: std::io::Error) -> Self {
        ImapError::Io(error)
    }
}

impl Display for ImapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImapError::Io(io) => write!(f, "I/O error: {io}"),
            ImapError::Timeout => f.write_str("Connection time-out"),
            ImapError::InvalidResponse(response) => write!(f, "Unexpected response: {response:?}"),
            ImapError::InvalidChallenge(response) => {
                write!(f, "Invalid auth challenge: {response}")
            }
            ImapError::TLSInvalidName => f.write_str("Invalid TLS name"),
            ImapError::Disconnected => f.write_str("Connection disconnected by peer"),
            ImapError::AuthenticationFailed => f.write_str("Authentication failed"),
        }
    }
}
