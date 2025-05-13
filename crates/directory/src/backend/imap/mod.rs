/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;
pub mod config;
pub mod lookup;
pub mod pool;
pub mod tls;

use std::{fmt::Display, sync::atomic::AtomicU64, time::Duration};

use ahash::AHashSet;
use deadpool::managed::Pool;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

pub struct ImapDirectory {
    pool: Pool<ImapConnectionManager>,
    domains: AHashSet<String>,
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
