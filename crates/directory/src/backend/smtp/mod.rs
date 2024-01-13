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

pub mod config;
pub mod lookup;
pub mod pool;

use ahash::AHashSet;
use deadpool::managed::Pool;
use mail_send::SmtpClientBuilder;
use smtp_proto::EhloResponse;
use store::Store;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub struct SmtpDirectory {
    pool: Pool<SmtpConnectionManager>,
    domains: AHashSet<String>,
    pub(crate) data_store: Store,
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
