/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{fmt::Display, sync::Arc, time::Duration};

use mail_send::Credentials;
use rustls::ServerName;
use smtp_proto::{
    request::{parser::Rfc5321Parser, AUTH},
    response::generate::BitToString,
    IntoString, AUTH_CRAM_MD5, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
    sync::mpsc,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::lookup::spawn::LoggedUnwrap;

use super::{Event, Item, LookupItem, RemoteLookup};

pub struct ImapAuthClient<T: AsyncRead + AsyncWrite> {
    stream: T,
    timeout: Duration,
}

pub struct ImapAuthClientBuilder {
    pub addr: String,
    timeout: Duration,
    tls_connector: TlsConnector,
    tls_hostname: String,
    tls_implicit: bool,
    mechanisms: u64,
}

impl ImapAuthClientBuilder {
    pub fn new(
        addr: String,
        timeout: Duration,
        tls_connector: TlsConnector,
        tls_hostname: String,
        tls_implicit: bool,
    ) -> Self {
        Self {
            addr,
            timeout,
            tls_connector,
            tls_hostname,
            tls_implicit,
            mechanisms: AUTH_PLAIN,
        }
    }

    pub async fn init(mut self) -> Self {
        let err = match self.connect().await {
            Ok(mut client) => match client.authentication_mechanisms().await {
                Ok(mechanisms) => {
                    client.logout().await.ok();
                    self.mechanisms = mechanisms;
                    return self;
                }
                Err(err) => err,
            },
            Err(err) => err,
        };
        tracing::warn!(
            context = "remote",
            event = "error",
            remote.addr = &self.addr,
            remote.protocol = "imap",
            "Could not obtain auth mechanisms: {}",
            err
        );

        self
    }

    pub async fn connect(&self) -> Result<ImapAuthClient<TlsStream<TcpStream>>, Error> {
        ImapAuthClient::connect(
            &self.addr,
            self.timeout,
            &self.tls_connector,
            &self.tls_hostname,
            self.tls_implicit,
        )
        .await
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Timeout,
    InvalidResponse(String),
    InvalidChallenge(String),
    AuthenticationFailed,
    TLSInvalidName,
    Disconnected,
}

impl RemoteLookup for Arc<ImapAuthClientBuilder> {
    fn spawn_lookup(&self, lookup: LookupItem, tx: mpsc::Sender<Event>) {
        let builder = self.clone();
        tokio::spawn(async move {
            if let Err(err) = builder.lookup(lookup, &tx).await {
                tracing::warn!(
                    context = "remote",
                    event = "error",
                    remote.addr = &builder.addr,
                    remote.protocol = "imap",
                    "Remote lookup failed: {}",
                    err
                );
                tx.send(Event::WorkerFailed).await.logged_unwrap();
            }
        });
    }
}

impl ImapAuthClientBuilder {
    pub async fn lookup(&self, lookup: LookupItem, tx: &mpsc::Sender<Event>) -> Result<(), Error> {
        match &lookup.item {
            Item::Authenticate(credentials) => {
                let mut client = self.connect().await?;
                let mechanism = match credentials {
                    Credentials::Plain { .. }
                        if (self.mechanisms & (AUTH_PLAIN | AUTH_LOGIN | AUTH_CRAM_MD5)) != 0 =>
                    {
                        if self.mechanisms & AUTH_CRAM_MD5 != 0 {
                            AUTH_CRAM_MD5
                        } else if self.mechanisms & AUTH_PLAIN != 0 {
                            AUTH_PLAIN
                        } else {
                            AUTH_LOGIN
                        }
                    }
                    Credentials::OAuthBearer { .. } if self.mechanisms & AUTH_OAUTHBEARER != 0 => {
                        AUTH_OAUTHBEARER
                    }
                    Credentials::XOauth2 { .. } if self.mechanisms & AUTH_XOAUTH2 != 0 => {
                        AUTH_XOAUTH2
                    }
                    _ => {
                        tracing::warn!(
                            context = "remote",
                            event = "error",
                            remote.addr = &self.addr,
                            remote.protocol = "imap",
                            "IMAP server does not offer any supported auth mechanisms.",
                        );
                        tx.send(Event::WorkerFailed).await.logged_unwrap();
                        return Ok(());
                    }
                };

                let result = match client.authenticate(mechanism, credentials).await {
                    Ok(_) => true,
                    Err(err) => match &err {
                        Error::AuthenticationFailed => false,
                        _ => return Err(err),
                    },
                };
                tx.send(Event::WorkerReady {
                    item: lookup.item,
                    result: Some(result),
                    next_lookup: None,
                })
                .await
                .logged_unwrap();
                lookup.result.send(result.into()).logged_unwrap();
            }
            _ => {
                tracing::warn!(
                    context = "remote",
                    event = "error",
                    remote.addr = &self.addr,
                    remote.protocol = "imap",
                    "IMAP does not support validating recipients.",
                );
                tx.send(Event::WorkerFailed).await.logged_unwrap();
            }
        }
        Ok(())
    }
}

impl ImapAuthClient<TcpStream> {
    async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapAuthClient<TlsStream<TcpStream>>, Error> {
        let line = tokio::time::timeout(self.timeout, async {
            self.write(b"C7 STARTTLS\r\n").await?;

            self.read_line().await
        })
        .await
        .map_err(|_| Error::Timeout)??;

        if matches!(line.get(..5), Some(b"C7 OK")) {
            self.into_tls(tls_connector, tls_hostname).await
        } else {
            Err(Error::InvalidResponse(line.into_string()))
        }
    }

    async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapAuthClient<TlsStream<TcpStream>>, Error> {
        tokio::time::timeout(self.timeout, async {
            Ok(ImapAuthClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(tls_hostname).map_err(|_| Error::TLSInvalidName)?,
                        self.stream,
                    )
                    .await?,
                timeout: self.timeout,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

impl ImapAuthClient<TlsStream<TcpStream>> {
    pub async fn connect(
        addr: impl ToSocketAddrs,
        timeout: Duration,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
        tls_implicit: bool,
    ) -> Result<Self, Error> {
        let mut client: ImapAuthClient<TcpStream> = tokio::time::timeout(timeout, async {
            match TcpStream::connect(addr).await {
                Ok(stream) => Ok(ImapAuthClient { stream, timeout }),
                Err(err) => Err(Error::Io(err)),
            }
        })
        .await
        .map_err(|_| Error::Timeout)??;

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

impl<T: AsyncRead + AsyncWrite + Unpin> ImapAuthClient<T> {
    pub async fn authenticate(
        &mut self,
        mechanism: u64,
        credentials: &Credentials<String>,
    ) -> Result<(), Error> {
        if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.write(
                format!(
                    "C3 AUTHENTICATE {} {}\r\n",
                    mechanism.to_mechanism(),
                    credentials
                        .encode(mechanism, "")
                        .map_err(|err| Error::InvalidChallenge(err.to_string()))?
                )
                .as_bytes(),
            )
            .await?;
        } else {
            self.write(format!("C3 AUTHENTICATE {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?;
        }
        let mut line = self.read_line().await?;

        for _ in 0..3 {
            if matches!(line.first(), Some(b'+')) {
                self.write(
                    format!(
                        "{}\r\n",
                        credentials
                            .encode(
                                mechanism,
                                std::str::from_utf8(line.get(2..).unwrap_or_default())
                                    .unwrap_or_default()
                            )
                            .map_err(|err| Error::InvalidChallenge(err.to_string()))?
                    )
                    .as_bytes(),
                )
                .await?;
                line = self.read_line().await?;
            } else if matches!(line.get(..5), Some(b"C3 OK")) {
                return Ok(());
            } else if matches!(line.get(..5), Some(b"C3 NO"))
                || matches!(line.get(..6), Some(b"C3 BAD"))
            {
                return Err(Error::AuthenticationFailed);
            } else {
                return Err(Error::InvalidResponse(line.into_string()));
            }
        }

        Err(Error::InvalidResponse(line.into_string()))
    }

    pub async fn authentication_mechanisms(&mut self) -> Result<u64, Error> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C0 CAPABILITY\r\n").await?;

            let line = self.read_line().await?;
            if !matches!(line.get(..12), Some(b"* CAPABILITY")) {
                return Err(Error::InvalidResponse(line.into_string()));
            }

            let mut line_iter = line.iter();
            let mut parser = Rfc5321Parser::new(&mut line_iter);
            let mut mechanisms = 0;

            'outer: while let Ok(ch) = parser.read_char() {
                if ch == b' ' {
                    loop {
                        if parser.hashed_value().unwrap_or(0) == AUTH && parser.stop_char == b'=' {
                            if let Ok(Some(mechanism)) = parser.mechanism() {
                                mechanisms |= mechanism;
                            }
                            match parser.stop_char {
                                b' ' => (),
                                b'\n' => break 'outer,
                                _ => break,
                            }
                        }
                    }
                } else if ch == b'\n' {
                    break;
                }
            }

            Ok(mechanisms)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn noop(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C8 NOOP\r\n").await?;
            self.read_line().await?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn logout(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C9 LOGOUT\r\n").await?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn expect_greeting(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            let line = self.read_line().await?;
            if matches!(line.get(..4), Some(b"* OK")) {
                Ok(())
            } else {
                Err(Error::InvalidResponse(line.into_string()))
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn read_line(&mut self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; 1024];
        let mut buf_extended = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                if matches!(buf.get(br - 1), Some(b'\n')) {
                    //println!("{:?}", std::str::from_utf8(&buf[..br]).unwrap());
                    return Ok(if buf_extended.is_empty() {
                        buf.truncate(br);
                        buf
                    } else {
                        buf_extended.extend_from_slice(&buf[..br]);
                        buf_extended
                    });
                } else if buf_extended.is_empty() {
                    buf_extended = buf[..br].to_vec();
                } else {
                    buf_extended.extend_from_slice(&buf[..br]);
                }
            } else {
                return Err(Error::Disconnected);
            }
        }
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(io) => write!(f, "I/O error: {io}"),
            Error::Timeout => f.write_str("Connection time-out"),
            Error::InvalidResponse(response) => write!(f, "Unexpected response: {response:?}"),
            Error::InvalidChallenge(response) => write!(f, "Invalid auth challenge: {response}"),
            Error::TLSInvalidName => f.write_str("Invalid TLS name"),
            Error::Disconnected => f.write_str("Connection disconnected by peer"),
            Error::AuthenticationFailed => f.write_str("Authentication failed"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::lookup::imap::ImapAuthClient;
    use mail_send::smtp::tls::build_tls_connector;
    use smtp_proto::{AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH, AUTH_XOAUTH2};
    use std::time::Duration;

    #[ignore]
    #[tokio::test]
    async fn imap_auth() {
        let connector = build_tls_connector(false);

        let mut client = ImapAuthClient::connect(
            "imap.gmail.com:993",
            Duration::from_secs(5),
            &connector,
            "imap.gmail.com",
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            AUTH_PLAIN | AUTH_XOAUTH | AUTH_XOAUTH2 | AUTH_OAUTHBEARER,
            client.authentication_mechanisms().await.unwrap()
        );
        client.logout().await.unwrap();
    }
}
