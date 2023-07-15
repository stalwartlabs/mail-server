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

use std::time::Duration;

use rustls::ServerName;
use smtp_proto::IntoString;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{client::TlsStream, TlsConnector};

use super::{ImapClient, ImapError};

impl ImapClient<TcpStream> {
    async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapClient<TlsStream<TcpStream>>, ImapError> {
        let line = tokio::time::timeout(self.timeout, async {
            self.write(b"C7 STARTTLS\r\n").await?;

            self.read_line().await
        })
        .await
        .map_err(|_| ImapError::Timeout)??;

        if matches!(line.get(..5), Some(b"C7 OK")) {
            self.into_tls(tls_connector, tls_hostname).await
        } else {
            Err(ImapError::InvalidResponse(line.into_string()))
        }
    }

    async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapClient<TlsStream<TcpStream>>, ImapError> {
        tokio::time::timeout(self.timeout, async {
            Ok(ImapClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(tls_hostname)
                            .map_err(|_| ImapError::TLSInvalidName)?,
                        self.stream,
                    )
                    .await?,
                timeout: self.timeout,
                mechanisms: self.mechanisms,
                is_valid: true,
            })
        })
        .await
        .map_err(|_| ImapError::Timeout)?
    }
}

impl ImapClient<TlsStream<TcpStream>> {
    pub async fn connect(
        addr: impl ToSocketAddrs,
        timeout: Duration,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
        tls_implicit: bool,
    ) -> Result<Self, ImapError> {
        let mut client: ImapClient<TcpStream> = tokio::time::timeout(timeout, async {
            match TcpStream::connect(addr).await {
                Ok(stream) => Ok(ImapClient {
                    stream,
                    timeout,
                    mechanisms: 0,
                    is_valid: true,
                }),
                Err(err) => Err(ImapError::Io(err)),
            }
        })
        .await
        .map_err(|_| ImapError::Timeout)??;

        if tls_implicit {
            let mut client = client.into_tls(tls_connector, tls_hostname).await?;
            client.expect_greeting().await?;
            Ok(client)
        } else {
            client.expect_greeting().await?;
            client.start_tls(tls_connector, tls_hostname).await
        }
    }
}
