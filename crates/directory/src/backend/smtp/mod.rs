/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod config;
pub mod lookup;
pub mod pool;

use ahash::AHashSet;
use deadpool::managed::Pool;
use mail_send::SmtpClientBuilder;
use smtp_proto::EhloResponse;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub struct SmtpDirectory {
    pool: Pool<SmtpConnectionManager>,
    domains: AHashSet<String>,
}

pub struct SmtpConnectionManager {
    builder: SmtpClientBuilder<String>,
    max_rcpt: usize,
    max_auth_errors: usize,
}

pub struct SmtpClient {
    client: mail_send::SmtpClient<TlsStream<TcpStream>>,
    capabilities: EhloResponse<String>,
    max_rcpt: usize,
    max_auth_errors: usize,
    num_rcpts: usize,
    num_auth_failures: usize,
    sent_mail_from: bool,
}
