/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, time::Instant};

use common::{
    config::smtp::session::{Milter, Stage},
    listener::SessionStream,
    DAEMON_NAME,
};
use mail_auth::AuthenticatedMessage;
use smtp_proto::{request::parser::Rfc5321Parser, IntoString};
use tokio::io::{AsyncRead, AsyncWrite};
use trc::MilterEvent;

use crate::{
    core::{Session, SessionAddress, SessionData},
    inbound::{milter::MilterClient, FilterResponse},
    queue::DomainPart,
};

use super::{Action, Error, Macros, Modification};

enum Rejection {
    Action(Action),
    Error(Error),
}

impl<T: SessionStream> Session<T> {
    pub async fn run_milters(
        &self,
        stage: Stage,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, FilterResponse> {
        let milters = &self.core.core.smtp.session.milters;
        if milters.is_empty() {
            return Ok(Vec::new());
        }

        let mut modifications = Vec::new();
        for milter in milters {
            if !milter.run_on_stage.contains(&stage)
                || !self
                    .core
                    .core
                    .eval_if(&milter.enable, self, self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }

            let time = Instant::now();
            match self.connect_and_run(milter, message).await {
                Ok(new_modifications) => {
                    trc::event!(
                        Milter(MilterEvent::ActionAccept),
                        SpanId = self.data.session_id,
                        Id = milter.id.to_string(),
                        Elapsed = time.elapsed(),
                    );

                    if !modifications.is_empty() {
                        // The message body can only be replaced once, so we need to remove
                        // any previous replacements.
                        if new_modifications
                            .iter()
                            .any(|m| matches!(m, Modification::ReplaceBody { .. }))
                        {
                            modifications
                                .retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                        }
                        modifications.extend(new_modifications);
                    } else {
                        modifications = new_modifications;
                    }
                }
                Err(Rejection::Action(action)) => {
                    trc::event!(
                        Milter(match &action {
                            Action::Discard => MilterEvent::ActionDiscard,
                            Action::Reject => MilterEvent::ActionReject,
                            Action::TempFail => MilterEvent::ActionTempFail,
                            Action::ReplyCode { .. } => {
                                MilterEvent::ActionReplyCode
                            }
                            Action::Shutdown => MilterEvent::ActionShutdown,
                            Action::ConnectionFailure => MilterEvent::ActionConnectionFailure,
                            Action::Accept | Action::Continue => unreachable!(),
                        }),
                        SpanId = self.data.session_id,
                        Id = milter.id.to_string(),
                        Elapsed = time.elapsed(),
                    );

                    return Err(match action {
                        Action::Discard => FilterResponse::accept(),
                        Action::Reject => FilterResponse::reject(),
                        Action::TempFail => FilterResponse::temp_fail(),
                        Action::ReplyCode { code, text } => {
                            let mut response = Vec::with_capacity(text.len() + 6);
                            response.extend_from_slice(code.as_slice());
                            response.push(b' ');
                            response.extend_from_slice(text.as_bytes());
                            if !text.ends_with('\n') {
                                response.extend_from_slice(b"\r\n");
                            }
                            FilterResponse {
                                message: response.into_string().into(),
                                disconnect: false,
                            }
                        }
                        Action::Shutdown => FilterResponse::shutdown(),
                        Action::ConnectionFailure => FilterResponse::default().disconnect(),
                        Action::Accept | Action::Continue => unreachable!(),
                    });
                }
                Err(Rejection::Error(err)) => {
                    let (code, details) = match err {
                        Error::Io(details) => {
                            (MilterEvent::IoError, trc::Value::from(details.to_string()))
                        }
                        Error::FrameTooLarge(size) => {
                            (MilterEvent::FrameTooLarge, trc::Value::from(size))
                        }
                        Error::FrameInvalid(bytes) => {
                            (MilterEvent::FrameInvalid, trc::Value::from(bytes))
                        }
                        Error::Unexpected(response) => (
                            MilterEvent::UnexpectedResponse,
                            trc::Value::from(response.to_string()),
                        ),
                        Error::Timeout => (MilterEvent::Timeout, trc::Value::None),
                        Error::TLSInvalidName => (MilterEvent::TlsInvalidName, trc::Value::None),
                        Error::Disconnected => (MilterEvent::Disconnected, trc::Value::None),
                    };

                    trc::event!(
                        Milter(code),
                        SpanId = self.data.session_id,
                        Id = milter.id.to_string(),
                        Details = details,
                        Elapsed = time.elapsed(),
                    );

                    if milter.tempfail_on_error {
                        return Err(FilterResponse::server_failure());
                    }
                }
            }
        }

        Ok(modifications)
    }

    async fn connect_and_run(
        &self,
        milter: &Milter,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, Rejection> {
        // Build client
        let client = MilterClient::connect(milter, self.data.session_id).await?;
        if !milter.tls {
            self.run(client, message).await
        } else {
            self.run(
                client
                    .into_tls(
                        if !milter.tls_allow_invalid_certs {
                            &self.core.inner.connectors.pki_verify
                        } else {
                            &self.core.inner.connectors.dummy_verify
                        },
                        &milter.hostname,
                    )
                    .await?,
                message,
            )
            .await
        }
    }

    async fn run<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut client: MilterClient<S>,
        message: Option<&AuthenticatedMessage<'_>>,
    ) -> Result<Vec<Modification>, Rejection> {
        // Option negotiation
        client.init().await?;

        // Connect stage
        let client_ptr = self
            .data
            .iprev
            .as_ref()
            .and_then(|ip_rev| ip_rev.ptr.as_ref())
            .and_then(|ptrs| ptrs.first());
        client
            .connection(
                client_ptr.unwrap_or(&self.data.helo_domain),
                self.data.remote_ip,
                self.data.remote_port,
                Macros::new()
                    .with_daemon_name(DAEMON_NAME)
                    .with_local_hostname(&self.hostname)
                    .with_client_address(self.data.remote_ip)
                    .with_client_port(self.data.remote_port)
                    .with_client_ptr(client_ptr.map(|p| p.as_str()).unwrap_or("unknown")),
            )
            .await?
            .assert_continue()?;

        // EHLO/HELO
        let (tls_version, tls_cipher) = self.stream.tls_version_and_cipher();
        client
            .helo(
                &self.data.helo_domain,
                Macros::new()
                    .with_cipher(tls_cipher.as_ref())
                    .with_tls_version(tls_version.as_ref()),
            )
            .await?
            .assert_continue()?;

        // Mail from
        if let Some(mail_from) = &self.data.mail_from {
            let addr = &mail_from.address_lcase;
            client
                .mail_from(
                    &format!("<{addr}>"),
                    None::<&[&str]>,
                    if !self.data.authenticated_as.is_empty() {
                        Macros::new()
                            .with_mail_address(addr)
                            .with_sasl_login_name(&self.data.authenticated_as)
                    } else {
                        Macros::new().with_mail_address(addr)
                    },
                )
                .await?
                .assert_continue()?;

            // Rcpt to
            for rcpt in &self.data.rcpt_to {
                client
                    .rcpt_to(
                        &format!("<{}>", rcpt.address_lcase),
                        None::<&[&str]>,
                        Macros::new().with_rcpt_address(&rcpt.address_lcase),
                    )
                    .await?
                    .assert_continue()?;
            }
        }

        if let Some(message) = message {
            // Data
            client.data().await?.assert_continue()?;

            // Headers
            client
                .headers(message.raw_parsed_headers().iter().map(|(k, v)| {
                    (
                        std::str::from_utf8(k).unwrap_or_default(),
                        std::str::from_utf8(v).unwrap_or_default(),
                    )
                }))
                .await?
                .assert_continue()?;

            // Message body
            let (action, modifications) = client.body(message.raw_message()).await?;
            action.assert_continue()?;

            // Quit
            let _ = client.quit().await;

            // Return modifications
            Ok(modifications)
        } else {
            // Quit
            let _ = client.quit().await;

            Ok(Vec::new())
        }
    }
}

impl SessionData {
    pub fn apply_milter_modifications(
        &mut self,
        modifications: Vec<Modification>,
        message: &AuthenticatedMessage<'_>,
    ) -> Option<Vec<u8>> {
        let mut body = Vec::new();
        let mut header_changes = Vec::new();
        let mut needs_rewrite = false;

        for modification in modifications {
            match modification {
                Modification::ChangeFrom { sender, mut args } => {
                    // Change sender
                    let sender = strip_brackets(&sender);
                    let address_lcase = sender.to_lowercase();
                    let mut mail_from = SessionAddress {
                        domain: address_lcase.domain_part().to_string(),
                        address_lcase,
                        address: sender,
                        flags: 0,
                        dsn_info: None,
                    };
                    if !args.is_empty() {
                        args.push('\n');
                        match Rfc5321Parser::new(&mut args.as_bytes().iter())
                            .mail_from_parameters(String::new())
                        {
                            Ok(addr) => {
                                mail_from.flags = addr.flags;
                                mail_from.dsn_info = addr.env_id;
                            }
                            Err(err) => {
                                trc::event!(
                                    Milter(MilterEvent::ParseError),
                                    SpanId = self.session_id,
                                    Details = "Failed to parse milter mailFrom parameters",
                                    Reason = err.to_string(),
                                );
                            }
                        }
                    }
                    self.mail_from = Some(mail_from);
                }
                Modification::AddRcpt {
                    recipient,
                    mut args,
                } => {
                    // Add recipient
                    let recipient = strip_brackets(&recipient);
                    if recipient.contains('@') {
                        let address_lcase = recipient.to_lowercase();
                        let mut rcpt = SessionAddress {
                            domain: address_lcase.domain_part().to_string(),
                            address_lcase,
                            address: recipient,
                            flags: 0,
                            dsn_info: None,
                        };
                        if !args.is_empty() {
                            args.push('\n');
                            match Rfc5321Parser::new(&mut args.as_bytes().iter())
                                .rcpt_to_parameters(String::new())
                            {
                                Ok(addr) => {
                                    rcpt.flags = addr.flags;
                                    rcpt.dsn_info = addr.orcpt;
                                }
                                Err(err) => {
                                    trc::event!(
                                        Milter(MilterEvent::ParseError),
                                        SpanId = self.session_id,
                                        Details = "Failed to parse milter rcptTo parameters",
                                        Reason = err.to_string(),
                                    );
                                }
                            }
                        }

                        if !self.rcpt_to.contains(&rcpt) {
                            self.rcpt_to.push(rcpt);
                        }
                    }
                }
                Modification::DeleteRcpt { recipient } => {
                    let recipient = strip_brackets(&recipient);
                    self.rcpt_to.retain(|r| r.address_lcase != recipient);
                }
                Modification::ReplaceBody { value } => {
                    body.extend(value);
                }
                Modification::AddHeader { name, value } => {
                    header_changes.push((0, name, value, false));
                }
                Modification::InsertHeader { index, name, value } => {
                    header_changes.push((index, name, value, false));
                    needs_rewrite = true;
                }
                Modification::ChangeHeader { index, name, value } => {
                    if value.is_empty()
                        || message
                            .raw_parsed_headers()
                            .iter()
                            .any(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                    {
                        header_changes.push((index, name, value, true));
                        needs_rewrite = true;
                    } else {
                        header_changes.push((0, name, value, false));
                    }
                }
                Modification::Quarantine { reason } => {
                    header_changes.push((0, "X-Quarantine".to_string(), reason, false));
                }
            }
        }

        // If there are no header changes return
        if header_changes.is_empty() {
            return if !body.is_empty() {
                let mut new_message = Vec::with_capacity(body.len() + message.raw_headers().len());
                new_message.extend_from_slice(message.raw_headers());
                new_message.extend(body);
                Some(new_message)
            } else {
                None
            };
        }

        let new_body = if !body.is_empty() {
            &body[..]
        } else {
            message.raw_body()
        };

        if needs_rewrite {
            let mut headers = message
                .raw_parsed_headers()
                .iter()
                .map(|(h, v)| (Cow::from(*h), Cow::from(*v)))
                .collect::<Vec<_>>();

            // Perform changes
            for (index, header_name, header_value, is_change) in header_changes {
                if is_change {
                    let mut header_count = 0;
                    for (pos, (name, value)) in headers.iter_mut().enumerate() {
                        if name.eq_ignore_ascii_case(header_name.as_bytes()) {
                            header_count += 1;
                            if header_count == index {
                                if !header_value.is_empty() {
                                    *value = Cow::from(header_value.into_bytes());
                                } else {
                                    headers.remove(pos);
                                }
                                break;
                            }
                        }
                    }
                } else {
                    let mut header_pos = 0;
                    if index > 0 {
                        let mut header_count = 0;
                        for (pos, (name, _)) in headers.iter().enumerate() {
                            if name.eq_ignore_ascii_case(header_name.as_bytes()) {
                                header_pos = pos;
                                header_count += 1;
                                if header_count == index {
                                    break;
                                }
                            }
                        }
                    }

                    headers.insert(
                        header_pos,
                        (
                            Cow::from(header_name.into_bytes()),
                            Cow::from(header_value.into_bytes()),
                        ),
                    );
                }
            }

            // Write new headers
            let mut new_message = Vec::with_capacity(
                new_body.len()
                    + message.raw_headers().len()
                    + headers
                        .iter()
                        .map(|(h, v)| h.len() + v.len() + 4)
                        .sum::<usize>(),
            );
            for (header, value) in headers {
                new_message.extend_from_slice(header.as_ref());
                if value.first().map_or(false, |c| c.is_ascii_whitespace()) {
                    new_message.extend_from_slice(b":");
                } else {
                    new_message.extend_from_slice(b": ");
                }
                new_message.extend_from_slice(value.as_ref());
                if !value.last().map_or(false, |c| *c == b'\n') {
                    new_message.extend_from_slice(b"\r\n");
                }
            }
            new_message.extend_from_slice(b"\r\n");
            new_message.extend(new_body);
            Some(new_message)
        } else {
            let mut new_message = Vec::with_capacity(
                new_body.len()
                    + message.raw_headers().len()
                    + header_changes
                        .iter()
                        .map(|(_, h, v, _)| h.len() + v.len() + 4)
                        .sum::<usize>(),
            );
            for (_, header, value, _) in header_changes {
                new_message.extend_from_slice(header.as_bytes());
                new_message.extend_from_slice(b": ");
                new_message.extend_from_slice(value.as_bytes());
                if !value.ends_with('\n') {
                    new_message.extend_from_slice(b"\r\n");
                }
            }
            new_message.extend_from_slice(message.raw_headers());
            new_message.extend(new_body);
            Some(new_message)
        }
    }
}

impl Action {
    fn assert_continue(self) -> Result<(), Rejection> {
        match self {
            Action::Continue | Action::Accept => Ok(()),
            action => Err(Rejection::Action(action)),
        }
    }
}

impl From<Error> for Rejection {
    fn from(err: Error) -> Self {
        Rejection::Error(err)
    }
}

fn strip_brackets(addr: &str) -> String {
    let addr = addr.trim();
    if let Some(addr) = addr.strip_prefix('<') {
        if let Some((addr, _)) = addr.rsplit_once('>') {
            addr.trim().to_string()
        } else {
            addr.trim().to_string()
        }
    } else {
        addr.to_string()
    }
}
