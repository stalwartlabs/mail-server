/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::{server::ServerProtocol, smtp::session::Mechanism},
    expr::{self, functions::ResolveVariable, *},
    listener::SessionStream,
};
use smtp_proto::{
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver,
        MAX_LINE_LENGTH,
    },
    *,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use trc::{NetworkEvent, SmtpEvent};

use crate::core::{Session, State};

use super::auth::SaslToken;

impl<T: SessionStream> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        let mut iter = bytes.iter();
        let mut state = std::mem::replace(&mut self.state, State::None);

        'outer: loop {
            match &mut state {
                State::Request(receiver) => loop {
                    match receiver.ingest(&mut iter, bytes) {
                        Ok(request) => match request {
                            Request::Rcpt { to } => {
                                self.handle_rcpt_to(to).await?;
                            }
                            Request::Mail { from } => {
                                self.handle_mail_from(from).await?;
                            }
                            Request::Ehlo { host } => {
                                if self.instance.protocol == ServerProtocol::Smtp {
                                    self.handle_ehlo(host, true).await?;
                                } else {
                                    trc::event!(
                                        Smtp(SmtpEvent::LhloExpected),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(b"500 5.5.1 Invalid command.\r\n").await?;
                                }
                            }
                            Request::Data => {
                                if self.can_send_data().await? {
                                    self.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                        .await?;
                                    self.data.message = Vec::with_capacity(1024);
                                    state = State::Data(DataReceiver::new());
                                    continue 'outer;
                                }
                            }
                            Request::Bdat {
                                chunk_size,
                                is_last,
                            } => {
                                state = if chunk_size + self.data.message.len()
                                    < self.params.max_message_size
                                {
                                    if self.data.message.is_empty() {
                                        self.data.message = Vec::with_capacity(chunk_size);
                                    } else {
                                        self.data.message.reserve(chunk_size);
                                    }
                                    State::Bdat(BdatReceiver::new(chunk_size, is_last))
                                } else {
                                    // Chunk is too large, ignore.
                                    State::DataTooLarge(DummyDataReceiver::new_bdat(chunk_size))
                                };
                                continue 'outer;
                            }
                            Request::Auth {
                                mechanism,
                                initial_response,
                            } => {
                                let auth: u64 = self
                                    .core
                                    .core
                                    .eval_if::<Mechanism, _>(
                                        &self.core.core.smtp.session.auth.mechanisms,
                                        self,
                                        self.data.session_id,
                                    )
                                    .await
                                    .unwrap_or_default()
                                    .into();
                                if auth == 0 || self.params.auth_directory.is_none() {
                                    trc::event!(
                                        Smtp(SmtpEvent::AuthNotAllowed),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(b"503 5.5.1 AUTH not allowed.\r\n").await?;
                                } else if !self.data.authenticated_as.is_empty() {
                                    trc::event!(
                                        Smtp(SmtpEvent::AlreadyAuthenticated),
                                        SpanId = self.data.session_id,
                                        AccountName = self.data.authenticated_as.clone(),
                                    );

                                    self.write(b"503 5.5.1 Already authenticated.\r\n").await?;
                                } else if let Some(mut token) =
                                    SaslToken::from_mechanism(mechanism & auth)
                                {
                                    if self
                                        .handle_sasl_response(
                                            &mut token,
                                            initial_response.as_bytes(),
                                        )
                                        .await?
                                    {
                                        state = State::Sasl(LineReceiver::new(token));
                                        continue 'outer;
                                    }
                                } else {
                                    trc::event!(
                                        Smtp(SmtpEvent::AuthMechanismNotSupported),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(
                                        b"554 5.7.8 Authentication mechanism not supported.\r\n",
                                    )
                                    .await?;
                                }
                            }
                            Request::Noop { .. } => {
                                trc::event!(Smtp(SmtpEvent::Noop), SpanId = self.data.session_id,);

                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Vrfy { value } => {
                                self.handle_vrfy(value).await?;
                            }
                            Request::Expn { value } => {
                                self.handle_expn(value).await?;
                            }
                            Request::StartTls => {
                                if !self.stream.is_tls() {
                                    if self.instance.acceptor.is_tls() {
                                        trc::event!(
                                            Smtp(SmtpEvent::StartTls),
                                            SpanId = self.data.session_id,
                                        );

                                        self.write(b"220 2.0.0 Ready to start TLS.\r\n").await?;
                                        #[cfg(any(test, feature = "test_mode"))]
                                        if self.data.helo_domain.contains("badtls") {
                                            return Err(());
                                        }
                                        self.state = State::default();
                                        return Ok(false);
                                    } else {
                                        trc::event!(
                                            Smtp(SmtpEvent::StartTlsUnavailable),
                                            SpanId = self.data.session_id,
                                        );

                                        self.write(b"502 5.7.0 TLS not available.\r\n").await?;
                                    }
                                } else {
                                    trc::event!(
                                        Smtp(SmtpEvent::StartTlsAlready),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(b"504 5.7.4 Already in TLS mode.\r\n").await?;
                                }
                            }
                            Request::Rset => {
                                trc::event!(Smtp(SmtpEvent::Rset), SpanId = self.data.session_id,);

                                self.reset();
                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Quit => {
                                trc::event!(Smtp(SmtpEvent::Quit), SpanId = self.data.session_id,);

                                self.write(b"221 2.0.0 Bye.\r\n").await?;
                                return Err(());
                            }
                            Request::Help { .. } => {
                                trc::event!(Smtp(SmtpEvent::Help), SpanId = self.data.session_id,);

                                self.write(b"250 2.0.0 Help can be found at https://stalw.art\r\n")
                                    .await?;
                            }
                            Request::Helo { host } => {
                                if self.instance.protocol == ServerProtocol::Smtp {
                                    self.handle_ehlo(host, false).await?;
                                } else {
                                    trc::event!(
                                        Smtp(SmtpEvent::LhloExpected),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(b"500 5.5.1 Invalid command: LHLO expected.\r\n")
                                        .await?;
                                }
                            }
                            Request::Lhlo { host } => {
                                if self.instance.protocol == ServerProtocol::Lmtp {
                                    self.handle_ehlo(host, true).await?;
                                } else {
                                    trc::event!(
                                        Smtp(SmtpEvent::EhloExpected),
                                        SpanId = self.data.session_id,
                                    );

                                    self.write(b"502 5.5.1 Invalid command: EHLO expected.\r\n")
                                        .await?;
                                }
                            }
                            cmd @ (Request::Etrn { .. }
                            | Request::Atrn { .. }
                            | Request::Burl { .. }) => {
                                trc::event!(
                                    Smtp(SmtpEvent::CommandNotImplemented),
                                    SpanId = self.data.session_id,
                                    Details = format!("{cmd:?}"),
                                );

                                self.write(b"502 5.5.1 Command not implemented.\r\n")
                                    .await?;
                            }
                        },
                        Err(err) => match err {
                            Error::NeedsMoreData { .. } => break 'outer,
                            Error::UnknownCommand | Error::InvalidResponse { .. } => {
                                trc::event!(
                                    Smtp(SmtpEvent::InvalidCommand),
                                    SpanId = self.data.session_id,
                                );

                                self.write(b"500 5.5.1 Invalid command.\r\n").await?;
                            }
                            Error::InvalidSenderAddress => {
                                trc::event!(
                                    Smtp(SmtpEvent::InvalidSenderAddress),
                                    SpanId = self.data.session_id,
                                );

                                self.write(b"501 5.1.8 Bad sender's system address.\r\n")
                                    .await?;
                            }
                            Error::InvalidRecipientAddress => {
                                trc::event!(
                                    Smtp(SmtpEvent::InvalidRecipientAddress),
                                    SpanId = self.data.session_id,
                                );

                                self.write(
                                    b"501 5.1.3 Bad destination mailbox address syntax.\r\n",
                                )
                                .await?;
                            }
                            Error::SyntaxError { syntax } => {
                                trc::event!(
                                    Smtp(SmtpEvent::SyntaxError),
                                    SpanId = self.data.session_id,
                                    Details = syntax
                                );

                                self.write(
                                    format!("501 5.5.2 Syntax error, expected: {syntax}\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Error::InvalidParameter { param } => {
                                trc::event!(
                                    Smtp(SmtpEvent::InvalidParameter),
                                    SpanId = self.data.session_id,
                                    Details = param
                                );

                                self.write(
                                    format!("501 5.5.4 Invalid parameter {param:?}.\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Error::UnsupportedParameter { param } => {
                                trc::event!(
                                    Smtp(SmtpEvent::UnsupportedParameter),
                                    SpanId = self.data.session_id,
                                    Details = param.clone()
                                );

                                self.write(
                                    format!("504 5.5.4 Unsupported parameter {param:?}.\r\n")
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Error::ResponseTooLong => {
                                state = State::RequestTooLarge(DummyLineReceiver::default());
                                continue 'outer;
                            }
                        },
                    }
                },
                State::Data(receiver) => {
                    if self.data.message.len() + bytes.len() < self.params.max_message_size {
                        if receiver.ingest(&mut iter, &mut self.data.message) {
                            let num_rcpts = self.data.rcpt_to.len();
                            let message = self.queue_message().await;
                            if !message.is_empty() {
                                if self.instance.protocol == ServerProtocol::Smtp {
                                    self.write(message.as_ref()).await?;
                                } else {
                                    for _ in 0..num_rcpts {
                                        self.write(message.as_ref()).await?;
                                    }
                                }
                                self.reset();
                                state = State::default();
                            } else {
                                // Disconnect requested
                                return Err(());
                            }
                        } else {
                            break 'outer;
                        }
                    } else {
                        state = State::DataTooLarge(DummyDataReceiver::new_data(receiver));
                    }
                }
                State::Bdat(receiver) => {
                    if receiver.ingest(&mut iter, &mut self.data.message) {
                        if self.can_send_data().await? {
                            if receiver.is_last {
                                let num_rcpts = self.data.rcpt_to.len();
                                let message = self.queue_message().await;
                                if !message.is_empty() {
                                    if self.instance.protocol == ServerProtocol::Smtp {
                                        self.write(message.as_ref()).await?;
                                    } else {
                                        for _ in 0..num_rcpts {
                                            self.write(message.as_ref()).await?;
                                        }
                                    }
                                    self.reset();
                                } else {
                                    // Disconnect requested
                                    return Err(());
                                }
                            } else {
                                self.write(b"250 2.6.0 Chunk accepted.\r\n").await?;
                            }
                        } else {
                            self.data.message = Vec::with_capacity(0);
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::Sasl(receiver) => {
                    if receiver.ingest(&mut iter) {
                        if receiver.buf.len() < MAX_LINE_LENGTH {
                            if self
                                .handle_sasl_response(&mut receiver.state, &receiver.buf)
                                .await?
                            {
                                receiver.buf.clear();
                                continue 'outer;
                            }
                        } else {
                            trc::event!(
                                Smtp(SmtpEvent::AuthExchangeTooLong),
                                SpanId = self.data.session_id,
                                Limit = MAX_LINE_LENGTH,
                            );

                            self.auth_error(
                                b"500 5.5.6 Authentication Exchange line is too long.\r\n",
                            )
                            .await?;
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::DataTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        trc::event!(
                            Smtp(SmtpEvent::MessageTooLarge),
                            SpanId = self.data.session_id,
                        );

                        self.data.message = Vec::with_capacity(0);
                        self.write(b"552 5.3.4 Message too big for system.\r\n")
                            .await?;
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::RequestTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        trc::event!(
                            Smtp(SmtpEvent::RequestTooLarge),
                            SpanId = self.data.session_id,
                        );

                        self.write(b"554 5.3.4 Line is too long.\r\n").await?;
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::None | State::Accepted(_) => unreachable!(),
            }
        }
        self.state = state;

        Ok(true)
    }
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn reset(&mut self) {
        self.data.mail_from = None;
        self.data.spf_mail_from = None;
        self.data.rcpt_to.clear();
        self.data.message = Vec::with_capacity(0);
        self.data.priority = 0;
        self.data.delivery_by = 0;
        self.data.future_release = 0;
    }

    #[inline(always)]
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        match self.stream.write_all(bytes).await {
            Ok(_) => match self.stream.flush().await {
                Ok(_) => {
                    trc::event!(
                        Smtp(SmtpEvent::RawOutput),
                        SpanId = self.data.session_id,
                        Size = bytes.len(),
                        Contents = trc::Value::from_maybe_string(bytes),
                    );

                    Ok(())
                }
                Err(err) => {
                    trc::event!(
                        Network(NetworkEvent::FlushError),
                        SpanId = self.data.session_id,
                        Reason = err.to_string(),
                    );
                    Err(())
                }
            },
            Err(err) => {
                trc::event!(
                    Network(NetworkEvent::WriteError),
                    SpanId = self.data.session_id,
                    Reason = err.to_string(),
                );

                Err(())
            }
        }
    }

    #[inline(always)]
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        match self.stream.read(bytes).await {
            Ok(len) => {
                trc::event!(
                    Smtp(SmtpEvent::RawInput),
                    SpanId = self.data.session_id,
                    Size = len,
                    Contents =
                        String::from_utf8_lossy(bytes.get(0..len).unwrap_or_default()).into_owned(),
                );

                Ok(len)
            }
            Err(err) => {
                trc::event!(
                    Network(NetworkEvent::ReadError),
                    SpanId = self.data.session_id,
                    Reason = err.to_string(),
                );

                Err(())
            }
        }
    }
}

impl<T: SessionStream> ResolveVariable for Session<T> {
    fn resolve_variable(&self, variable: u32) -> expr::Variable<'_> {
        match variable {
            V_RECIPIENT => self
                .data
                .rcpt_to
                .last()
                .map(|r| r.address_lcase.as_str())
                .unwrap_or_default()
                .into(),
            V_RECIPIENT_DOMAIN => self
                .data
                .rcpt_to
                .last()
                .map(|r| r.domain.as_str())
                .unwrap_or_default()
                .into(),
            V_RECIPIENTS => self
                .data
                .rcpt_to
                .iter()
                .map(|r| Variable::String(r.address_lcase.as_str().into()))
                .collect::<Vec<_>>()
                .into(),
            V_SENDER => self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.address_lcase.as_str())
                .unwrap_or_default()
                .into(),
            V_SENDER_DOMAIN => self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.domain.as_str())
                .unwrap_or_default()
                .into(),
            V_HELO_DOMAIN => self.data.helo_domain.as_str().into(),
            V_AUTHENTICATED_AS => self.data.authenticated_as.as_str().into(),
            V_LISTENER => self.instance.id.as_str().into(),
            V_REMOTE_IP => self.data.remote_ip_str.as_str().into(),
            V_REMOTE_PORT => self.data.remote_port.into(),
            V_LOCAL_IP => self.data.local_ip_str.as_str().into(),
            V_LOCAL_PORT => self.data.local_port.into(),
            V_TLS => self.stream.is_tls().into(),
            V_PRIORITY => self.data.priority.to_string().into(),
            V_PROTOCOL => self.instance.protocol.as_str().into(),
            _ => expr::Variable::default(),
        }
    }
}
