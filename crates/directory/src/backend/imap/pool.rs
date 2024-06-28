/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use deadpool::managed;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::{ImapClient, ImapConnectionManager, ImapError};

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
