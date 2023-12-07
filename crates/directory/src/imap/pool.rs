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

use std::sync::atomic::Ordering;

use async_trait::async_trait;
use deadpool::managed;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::{ImapClient, ImapConnectionManager, ImapError};

#[async_trait]
impl managed::Manager for ImapConnectionManager {
    type Type = ImapClient<TlsStream<TcpStream>>;
    type Error = ImapError;

    async fn create(&self) -> Result<ImapClient<TlsStream<TcpStream>>, ImapError> {
        let mut conn = ImapClient::connect(
            &self.addr,
            self.timeout,
            &self.tls_connector,
            &self.tls_hostname,
            self.tls_implicit,
        )
        .await?;

        // Obtain the list of supported authentication mechanisms.
        conn.mechanisms = self.mechanisms.load(Ordering::Relaxed);
        if conn.mechanisms == 0 {
            conn.mechanisms = conn.authentication_mechanisms().await?;
            self.mechanisms.store(conn.mechanisms, Ordering::Relaxed);
        }

        Ok(conn)
    }

    async fn recycle(
        &self,
        conn: &mut ImapClient<TlsStream<TcpStream>>,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<ImapError> {
        conn.noop()
            .await
            .map(|_| ())
            .map_err(managed::RecycleError::Backend)
    }
}
