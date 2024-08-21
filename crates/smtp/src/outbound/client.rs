/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use mail_send::{smtp::AssertReply, Credentials};
use rustls::ClientConnection;
use rustls_pki_types::ServerName;
use smtp_proto::{
    response::{
        generate::BitToString,
        parser::{ResponseReceiver, MAX_RESPONSE_LENGTH},
    },
    EhloResponse, Response, AUTH_CRAM_MD5, AUTH_DIGEST_MD5, AUTH_LOGIN, AUTH_OAUTHBEARER,
    AUTH_PLAIN, AUTH_XOAUTH2, EXT_START_TLS,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use trc::DeliveryEvent;

use crate::queue::{Error, Message, Status};

use super::session::SessionParams;

pub struct SmtpClient<T: AsyncRead + AsyncWrite> {
    pub stream: T,
    pub timeout: Duration,
    pub session_id: u64,
}

impl<T: AsyncRead + AsyncWrite + Unpin> SmtpClient<T> {
    pub async fn authenticate<U>(
        &mut self,
        credentials: impl AsRef<Credentials<U>>,
        capabilities: impl AsRef<EhloResponse<String>>,
    ) -> mail_send::Result<&mut Self>
    where
        U: AsRef<str> + PartialEq + Eq + std::hash::Hash,
    {
        let credentials = credentials.as_ref();
        let capabilities = capabilities.as_ref();
        let mut available_mechanisms = match &credentials {
            Credentials::Plain { .. } => AUTH_CRAM_MD5 | AUTH_DIGEST_MD5 | AUTH_LOGIN | AUTH_PLAIN,
            Credentials::OAuthBearer { .. } => AUTH_OAUTHBEARER,
            Credentials::XOauth2 { .. } => AUTH_XOAUTH2,
        } & capabilities.auth_mechanisms;

        // Try authenticating from most secure to least secure
        let mut has_err = None;
        let mut has_failed = false;

        while available_mechanisms != 0 && !has_failed {
            let mechanism = 1 << ((63 - available_mechanisms.leading_zeros()) as u64);
            available_mechanisms ^= mechanism;
            match self.auth(mechanism, credentials).await {
                Ok(_) => {
                    return Ok(self);
                }
                Err(err) => match err {
                    mail_send::Error::UnexpectedReply(reply) => {
                        has_failed = reply.code() == 535;
                        has_err = reply.into();
                    }
                    mail_send::Error::UnsupportedAuthMechanism => (),
                    _ => return Err(err),
                },
            }
        }

        if let Some(has_err) = has_err {
            Err(mail_send::Error::AuthenticationFailed(has_err))
        } else {
            Err(mail_send::Error::UnsupportedAuthMechanism)
        }
    }

    pub(crate) async fn auth<U>(
        &mut self,
        mechanism: u64,
        credentials: &Credentials<U>,
    ) -> mail_send::Result<()>
    where
        U: AsRef<str> + PartialEq + Eq + std::hash::Hash,
    {
        let mut reply = if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.cmd(
                format!(
                    "AUTH {} {}\r\n",
                    mechanism.to_mechanism(),
                    credentials.encode(mechanism, "")?,
                )
                .as_bytes(),
            )
            .await?
        } else {
            self.cmd(format!("AUTH {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?
        };

        for _ in 0..3 {
            match reply.code() {
                334 => {
                    reply = self
                        .cmd(
                            format!("{}\r\n", credentials.encode(mechanism, reply.message())?)
                                .as_bytes(),
                        )
                        .await?;
                }
                235 => {
                    return Ok(());
                }
                _ => {
                    return Err(mail_send::Error::UnexpectedReply(reply));
                }
            }
        }

        Err(mail_send::Error::UnexpectedReply(reply))
    }

    pub async fn read_greeting(&mut self, hostname: &str) -> Result<(), Status<(), Error>> {
        tokio::time::timeout(self.timeout, self.read())
            .await
            .map_err(|_| Status::timeout(hostname, "reading greeting"))?
            .and_then(|r| r.assert_code(220))
            .map_err(|err| Status::from_smtp_error(hostname, "", err))
    }

    pub async fn read_smtp_data_response(
        &mut self,
        hostname: &str,
        bdat_cmd: &Option<String>,
    ) -> Result<Response<String>, Status<(), Error>> {
        tokio::time::timeout(self.timeout, self.read())
            .await
            .map_err(|_| Status::timeout(hostname, "reading SMTP DATA response"))?
            .map_err(|err| {
                Status::from_smtp_error(hostname, bdat_cmd.as_deref().unwrap_or("DATA"), err)
            })
    }

    pub async fn read_lmtp_data_response(
        &mut self,
        hostname: &str,
        num_responses: usize,
    ) -> Result<Vec<Response<String>>, Status<(), Error>> {
        tokio::time::timeout(self.timeout, async { self.read_many(num_responses).await })
            .await
            .map_err(|_| Status::timeout(hostname, "reading LMTP DATA responses"))?
            .map_err(|err| Status::from_smtp_error(hostname, "", err))
    }

    pub async fn write_chunks(&mut self, chunks: &[&[u8]]) -> Result<(), mail_send::Error> {
        for chunk in chunks {
            self.stream
                .write_all(chunk)
                .await
                .map_err(mail_send::Error::from)?;
        }
        self.stream.flush().await.map_err(mail_send::Error::from)
    }

    pub async fn send_message(
        &mut self,
        message: &Message,
        bdat_cmd: &Option<String>,
        params: &SessionParams<'_>,
    ) -> Result<(), Status<(), Error>> {
        match params
            .core
            .core
            .storage
            .blob
            .get_blob(message.blob_hash.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw_message)) => tokio::time::timeout(params.timeout_data, async {
                if let Some(bdat_cmd) = bdat_cmd {
                    trc::event!(
                        Delivery(DeliveryEvent::RawOutput),
                        SpanId = self.session_id,
                        Contents = bdat_cmd.clone(),
                        Size = bdat_cmd.len()
                    );

                    self.write_chunks(&[bdat_cmd.as_bytes(), &raw_message])
                        .await
                } else {
                    trc::event!(
                        Delivery(DeliveryEvent::RawOutput),
                        SpanId = self.session_id,
                        Contents = "DATA\r\n",
                        Size = 6
                    );

                    self.write_chunks(&[b"DATA\r\n"]).await?;
                    self.read().await?.assert_code(354)?;
                    self.write_message(&raw_message)
                        .await
                        .map_err(mail_send::Error::from)
                }
            })
            .await
            .map_err(|_| Status::timeout(params.hostname, "sending message"))?
            .map_err(|err| {
                Status::from_smtp_error(params.hostname, bdat_cmd.as_deref().unwrap_or("DATA"), err)
            }),
            Ok(None) => {
                trc::event!(
                    Queue(trc::QueueEvent::BlobNotFound),
                    SpanId = message.span_id,
                    BlobId = message.blob_hash.to_hex(),
                    CausedBy = trc::location!()
                );
                Err(Status::TemporaryFailure(Error::Io(
                    "Queue system error.".to_string(),
                )))
            }
            Err(err) => {
                trc::error!(err
                    .span_id(message.span_id)
                    .details("Failed to fetch blobId")
                    .caused_by(trc::location!()));

                Err(Status::TemporaryFailure(Error::Io(
                    "Queue system error.".to_string(),
                )))
            }
        }
    }

    pub async fn say_helo(
        &mut self,
        params: &SessionParams<'_>,
    ) -> Result<EhloResponse<String>, Status<(), Error>> {
        let cmd = if params.is_smtp {
            format!("EHLO {}\r\n", params.local_hostname)
        } else {
            format!("LHLO {}\r\n", params.local_hostname)
        };

        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = cmd.clone(),
            Size = cmd.len()
        );

        tokio::time::timeout(params.timeout_ehlo, async {
            self.stream.write_all(cmd.as_bytes()).await?;
            self.stream.flush().await?;
            self.read_ehlo().await
        })
        .await
        .map_err(|_| Status::timeout(params.hostname, "reading EHLO response"))?
        .map_err(|err| Status::from_smtp_error(params.hostname, &cmd, err))
    }

    pub async fn quit(mut self: SmtpClient<T>) {
        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = "QUIT\r\n",
            Size = 6
        );

        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            if self.stream.write_all(b"QUIT\r\n").await.is_ok() && self.stream.flush().await.is_ok()
            {
                let mut buf = [0u8; 128];
                let _ = self.stream.read(&mut buf).await;
            }
        })
        .await;
    }

    pub async fn read_ehlo(&mut self) -> mail_send::Result<EhloResponse<String>> {
        let mut buf = vec![0u8; 8192];
        let mut buf_concat = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br == 0 {
                return Err(mail_send::Error::UnparseableReply);
            }

            trc::event!(
                Delivery(DeliveryEvent::RawInput),
                SpanId = self.session_id,
                Contents = trc::Value::from_maybe_string(&buf[..br]),
                Size = br,
            );

            let mut iter = if buf_concat.is_empty() {
                buf[..br].iter()
            } else if br + buf_concat.len() < MAX_RESPONSE_LENGTH {
                buf_concat.extend_from_slice(&buf[..br]);
                buf_concat.iter()
            } else {
                return Err(mail_send::Error::UnparseableReply);
            };

            match EhloResponse::parse(&mut iter) {
                Ok(reply) => return Ok(reply),
                Err(err) => match err {
                    smtp_proto::Error::NeedsMoreData { .. } => {
                        if buf_concat.is_empty() {
                            buf_concat = buf[..br].to_vec();
                        }
                    }
                    smtp_proto::Error::InvalidResponse { code } => {
                        match ResponseReceiver::from_code(code).parse(&mut iter) {
                            Ok(response) => {
                                return Err(mail_send::Error::UnexpectedReply(response));
                            }
                            Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                                if buf_concat.is_empty() {
                                    buf_concat = buf[..br].to_vec();
                                }
                            }
                            Err(_) => return Err(mail_send::Error::UnparseableReply),
                        }
                    }
                    _ => {
                        return Err(mail_send::Error::UnparseableReply);
                    }
                },
            }
        }
    }

    pub async fn read(&mut self) -> mail_send::Result<Response<String>> {
        let mut buf = vec![0u8; 8192];
        let mut parser = ResponseReceiver::default();

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                trc::event!(
                    Delivery(DeliveryEvent::RawInput),
                    SpanId = self.session_id,
                    Contents = trc::Value::from_maybe_string(&buf[..br]),
                    Size = br
                );

                match parser.parse(&mut buf[..br].iter()) {
                    Ok(reply) => return Ok(reply),
                    Err(err) => match err {
                        smtp_proto::Error::NeedsMoreData { .. } => (),
                        _ => {
                            return Err(mail_send::Error::UnparseableReply);
                        }
                    },
                }
            } else {
                return Err(mail_send::Error::UnparseableReply);
            }
        }
    }

    pub async fn read_many(&mut self, num: usize) -> mail_send::Result<Vec<Response<String>>> {
        let mut buf = vec![0u8; 1024];
        let mut response = Vec::with_capacity(num);
        let mut parser = ResponseReceiver::default();

        'outer: loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                let mut iter = buf[..br].iter();

                trc::event!(
                    Delivery(DeliveryEvent::RawInput),
                    SpanId = self.session_id,
                    Contents = trc::Value::from_maybe_string(&buf[..br]),
                    Size = br
                );

                loop {
                    match parser.parse(&mut iter) {
                        Ok(reply) => {
                            response.push(reply);
                            if response.len() != num {
                                parser.reset();
                            } else {
                                break 'outer;
                            }
                        }
                        Err(err) => match err {
                            smtp_proto::Error::NeedsMoreData { .. } => break,
                            _ => {
                                return Err(mail_send::Error::UnparseableReply);
                            }
                        },
                    }
                }
            } else {
                return Err(mail_send::Error::UnparseableReply);
            }
        }

        Ok(response)
    }

    /// Sends a command to the SMTP server and waits for a reply.
    pub async fn cmd(&mut self, cmd: impl AsRef<[u8]>) -> mail_send::Result<Response<String>> {
        tokio::time::timeout(self.timeout, async {
            let cmd = cmd.as_ref();

            trc::event!(
                Delivery(DeliveryEvent::RawOutput),
                SpanId = self.session_id,
                Contents = trc::Value::from_maybe_string(cmd),
                Size = cmd.len()
            );

            self.stream.write_all(cmd).await?;
            self.stream.flush().await?;
            self.read().await
        })
        .await
        .map_err(|_| mail_send::Error::Timeout)?
    }

    pub async fn write_message(&mut self, message: &[u8]) -> tokio::io::Result<()> {
        // Transparency procedure
        let mut is_cr_or_lf = false;

        // As per RFC 5322bis, section 2.3:
        // CR and LF MUST only occur together as CRLF; they MUST NOT appear
        // independently in the body.
        // For this reason, we apply the transparency procedure when there is
        // a CR or LF followed by a dot.

        trc::event!(
            Delivery(DeliveryEvent::RawOutput),
            SpanId = self.session_id,
            Contents = "[message]",
            Size = message.len() + 5
        );

        let mut last_pos = 0;
        for (pos, byte) in message.iter().enumerate() {
            if *byte == b'.' && is_cr_or_lf {
                if let Some(bytes) = message.get(last_pos..pos) {
                    self.stream.write_all(bytes).await?;
                    self.stream.write_all(b".").await?;
                    last_pos = pos;
                }
                is_cr_or_lf = false;
            } else {
                is_cr_or_lf = *byte == b'\n' || *byte == b'\r';
            }
        }
        if let Some(bytes) = message.get(last_pos..) {
            self.stream.write_all(bytes).await?;
        }
        self.stream.write_all("\r\n.\r\n".as_bytes()).await?;
        self.stream.flush().await
    }
}

impl SmtpClient<TcpStream> {
    /// Upgrade the connection to TLS.
    pub async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> mail_send::Result<SmtpClient<TlsStream<TcpStream>>> {
        // Send STARTTLS command
        self.cmd(b"STARTTLS\r\n")
            .await?
            .assert_positive_completion()?;

        self.into_tls(tls_connector, hostname).await
    }

    pub async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        hostname: &str,
    ) -> mail_send::Result<SmtpClient<TlsStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, async {
            Ok(SmtpClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(hostname)
                            .map_err(|_| mail_send::Error::InvalidTLSName)?
                            .to_owned(),
                        self.stream,
                    )
                    .await
                    .map_err(|err| {
                        let kind = err.kind();
                        if let Some(inner) = err.into_inner() {
                            match inner.downcast::<rustls::Error>() {
                                Ok(error) => mail_send::Error::Tls(error),
                                Err(error) => {
                                    mail_send::Error::Io(std::io::Error::new(kind, error))
                                }
                            }
                        } else {
                            mail_send::Error::Io(std::io::Error::new(kind, "Unspecified"))
                        }
                    })?,
                timeout: self.timeout,
                session_id: self.session_id,
            })
        })
        .await
        .map_err(|_| mail_send::Error::Timeout)?
    }
}

impl SmtpClient<TcpStream> {
    /// Connects to a remote host address
    pub async fn connect(
        remote_addr: SocketAddr,
        timeout: Duration,
        session_id: u64,
    ) -> mail_send::Result<Self> {
        tokio::time::timeout(timeout, async {
            Ok(SmtpClient {
                stream: TcpStream::connect(remote_addr).await?,
                timeout,
                session_id,
            })
        })
        .await
        .map_err(|_| mail_send::Error::Timeout)?
    }

    /// Connects to a remote host address using the provided local IP
    pub async fn connect_using(
        local_ip: IpAddr,
        remote_addr: SocketAddr,
        timeout: Duration,
        session_id: u64,
    ) -> mail_send::Result<Self> {
        tokio::time::timeout(timeout, async {
            let socket = if local_ip.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(local_ip, 0))?;

            Ok(SmtpClient {
                stream: socket.connect(remote_addr).await?,
                timeout,
                session_id,
            })
        })
        .await
        .map_err(|_| mail_send::Error::Timeout)?
    }

    pub async fn try_start_tls(
        mut self,
        tls_connector: &TlsConnector,
        hostname: &str,
        capabilities: &EhloResponse<String>,
    ) -> StartTlsResult {
        if capabilities.has_capability(EXT_START_TLS) {
            match self.cmd("STARTTLS\r\n").await {
                Ok(response) => {
                    if response.code() == 220 {
                        match self.into_tls(tls_connector, hostname).await {
                            Ok(smtp_client) => StartTlsResult::Success { smtp_client },
                            Err(error) => StartTlsResult::Error { error },
                        }
                    } else {
                        StartTlsResult::Unavailable {
                            response: response.into(),
                            smtp_client: self,
                        }
                    }
                }
                Err(error) => StartTlsResult::Error { error },
            }
        } else {
            StartTlsResult::Unavailable {
                smtp_client: self,
                response: None,
            }
        }
    }
}

impl SmtpClient<TlsStream<TcpStream>> {
    pub fn tls_connection(&self) -> &ClientConnection {
        self.stream.get_ref().1
    }
}

pub enum StartTlsResult {
    Success {
        smtp_client: SmtpClient<TlsStream<TcpStream>>,
    },
    Error {
        error: mail_send::Error,
    },
    Unavailable {
        response: Option<Response<String>>,
        smtp_client: SmtpClient<TcpStream>,
    },
}

pub(crate) fn from_mail_send_error(error: &mail_send::Error) -> trc::Error {
    let event = trc::EventType::Smtp(trc::SmtpEvent::Error).into_err();
    match error {
        mail_send::Error::Io(err) => event.details("I/O Error").reason(err),
        mail_send::Error::Tls(err) => event.details("TLS Error").reason(err),
        mail_send::Error::Base64(err) => event.details("Base64 Error").reason(err),
        mail_send::Error::Auth(err) => event.details("SMTP Authentication Error").reason(err),
        mail_send::Error::UnparseableReply => event.details("Unparseable SMTP Reply"),
        mail_send::Error::UnexpectedReply(reply) => event
            .details("Unexpected SMTP Response")
            .ctx(trc::Key::Code, reply.code)
            .ctx(trc::Key::Reason, reply.message.clone()),
        mail_send::Error::AuthenticationFailed(reply) => event
            .details("SMTP Authentication Failed")
            .ctx(trc::Key::Code, reply.code)
            .ctx(trc::Key::Reason, reply.message.clone()),
        mail_send::Error::InvalidTLSName => event.details("Invalid TLS Name"),
        mail_send::Error::MissingCredentials => event.details("Missing Authentication Credentials"),
        mail_send::Error::MissingMailFrom => event.details("Missing Message Sender"),
        mail_send::Error::MissingRcptTo => event.details("Missing Message Recipients"),
        mail_send::Error::UnsupportedAuthMechanism => {
            event.details("Unsupported Authentication Mechanism")
        }
        mail_send::Error::Timeout => event.details("Connection Timeout"),
        mail_send::Error::MissingStartTls => event.details("STARTTLS not available"),
    }
}

pub(crate) fn from_error_status(status: &Status<(), Error>) -> trc::Error {
    let event = trc::EventType::Smtp(trc::SmtpEvent::Error).into_err();
    let err = match status {
        Status::TemporaryFailure(err) | Status::PermanentFailure(err) => err,
        Status::Scheduled | Status::Completed(_) => return event, // This should not happen
    };

    match err {
        Error::DnsError(err) => event.details("DNS Error").reason(err),
        Error::UnexpectedResponse(reply) => event
            .details("Unexpected SMTP Response")
            .ctx(trc::Key::Code, reply.response.code)
            .ctx(trc::Key::Reason, reply.response.message.clone()),
        Error::ConnectionError(err) => event
            .details("Connection Error")
            .ctx(trc::Key::Reason, err.details.clone()),
        Error::TlsError(err) => event
            .details("TLS Error")
            .ctx(trc::Key::Reason, err.details.clone()),
        Error::DaneError(err) => event
            .details("DANE Error")
            .ctx(trc::Key::Reason, err.details.clone()),
        Error::MtaStsError(err) => event.details("MTA-STS Error").reason(err),
        Error::RateLimited => todo!(),
        Error::ConcurrencyLimited => todo!(),
        Error::Io(err) => event.details("I/O Error").reason(err),
    }
}
