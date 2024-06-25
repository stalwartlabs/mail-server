/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::RequireOptional;
use mail_send::{smtp::AssertReply, Credentials, SmtpClient};
use smtp_proto::{
    EhloResponse, Response, Severity, EXT_CHUNKING, EXT_DSN, EXT_REQUIRE_TLS, EXT_SIZE,
    EXT_SMTP_UTF8, EXT_START_TLS, MAIL_REQUIRETLS, MAIL_RET_FULL, MAIL_RET_HDRS, MAIL_SMTPUTF8,
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use std::fmt::Write;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{
    core::SMTP,
    queue::{ErrorDetails, HostResponse, RCPT_STATUS_CHANGED},
};

use crate::queue::{Error, Message, Recipient, Status};

use super::TlsStrategy;

pub struct SessionParams<'x> {
    pub span: &'x tracing::Span,
    pub core: &'x SMTP,
    pub hostname: &'x str,
    pub credentials: Option<&'x Credentials<String>>,
    pub is_smtp: bool,
    pub local_hostname: &'x str,
    pub timeout_ehlo: Duration,
    pub timeout_mail: Duration,
    pub timeout_rcpt: Duration,
    pub timeout_data: Duration,
}

impl Message {
    pub async fn deliver<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut smtp_client: SmtpClient<T>,
        recipients: impl Iterator<Item = &mut Recipient>,
        params: SessionParams<'_>,
    ) -> Status<(), Error> {
        // Obtain capabilities
        let capabilities = match say_helo(&mut smtp_client, &params).await {
            Ok(capabilities) => capabilities,
            Err(status) => {
                tracing::info!(
                    parent: params.span,
                    context = "ehlo",
                    event = "rejected",
                    mx = &params.hostname,
                    reason = %status,
                );
                quit(smtp_client).await;
                return status;
            }
        };

        // Authenticate
        if let Some(credentials) = params.credentials {
            if let Err(err) = smtp_client.authenticate(credentials, &capabilities).await {
                tracing::info!(
                    parent: params.span,
                    context = "auth",
                    event = "failed",
                    mx = &params.hostname,
                    reason = %err,
                );
                quit(smtp_client).await;
                return Status::from_smtp_error(params.hostname, "AUTH ...", err);
            }

            // Refresh capabilities
            // Disabled as some SMTP servers deauthenticate after EHLO
            /*capabilities = match say_helo(&mut smtp_client, &params).await {
                Ok(capabilities) => capabilities,
                Err(status) => {
                    tracing::info!(
                        parent: params.span,
                        context = "ehlo",
                        event = "rejected",
                        mx = &params.hostname,
                        reason = %status,
                    );
                    quit(smtp_client).await;
                    return status;
                }
            };*/
        }

        // MAIL FROM
        smtp_client.timeout = params.timeout_mail;
        let cmd = self.build_mail_from(&capabilities);
        if let Err(err) = smtp_client
            .cmd(cmd.as_bytes())
            .await
            .and_then(|r| r.assert_positive_completion())
        {
            tracing::info!(
                parent: params.span,
                context = "sender",
                event = "rejected",
                mx = &params.hostname,
                reason = %err,
            );
            quit(smtp_client).await;
            return Status::from_smtp_error(params.hostname, &cmd, err);
        }

        // RCPT TO
        let mut total_rcpt = 0;
        let mut total_completed = 0;
        let mut accepted_rcpts = Vec::new();
        smtp_client.timeout = params.timeout_rcpt;
        for rcpt in recipients {
            total_rcpt += 1;
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                total_completed += 1;
                continue;
            }

            let cmd = self.build_rcpt_to(rcpt, &capabilities);
            match smtp_client.cmd(cmd.as_bytes()).await {
                Ok(response) => match response.severity() {
                    Severity::PositiveCompletion => {
                        accepted_rcpts.push((
                            rcpt,
                            Status::Completed(HostResponse {
                                hostname: params.hostname.to_string(),
                                response,
                            }),
                        ));
                    }
                    severity => {
                        tracing::info!(
                            parent: params.span,
                            context = "rcpt",
                            event = "rejected",
                            rcpt = rcpt.address,
                            mx = &params.hostname,
                            reason = %response,
                        );

                        let response = HostResponse {
                            hostname: ErrorDetails {
                                entity: params.hostname.to_string(),
                                details: cmd.trim().to_string(),
                            },
                            response,
                        };
                        rcpt.flags |= RCPT_STATUS_CHANGED;
                        rcpt.status = if severity == Severity::PermanentNegativeCompletion {
                            total_completed += 1;
                            Status::PermanentFailure(response)
                        } else {
                            Status::TemporaryFailure(response)
                        };
                    }
                },
                Err(err) => {
                    tracing::info!(
                        parent: params.span,
                        context = "rcpt",
                        event = "failed",
                        mx = &params.hostname,
                        rcpt = rcpt.address,
                        reason = %err,
                    );

                    // Something went wrong, abort.
                    quit(smtp_client).await;
                    return Status::from_smtp_error(params.hostname, "", err);
                }
            }
        }

        // Send message
        if !accepted_rcpts.is_empty() {
            let bdat_cmd = if capabilities.has_capability(EXT_CHUNKING) {
                format!("BDAT {} LAST\r\n", self.size).into()
            } else {
                None
            };

            if let Err(status) = send_message(&mut smtp_client, self, &bdat_cmd, &params).await {
                tracing::info!(
                    parent: params.span,
                    context = "message",
                    event = "rejected",
                    mx = &params.hostname,
                    reason = %status,
                );

                quit(smtp_client).await;
                return status;
            }

            if params.is_smtp {
                // Handle SMTP response
                match read_smtp_data_response(&mut smtp_client, params.hostname, &bdat_cmd).await {
                    Ok(response) => {
                        // Mark recipients as delivered
                        if response.code() == 250 {
                            for (rcpt, status) in accepted_rcpts {
                                tracing::info!(
                                    parent: params.span,
                                    context = "rcpt",
                                    event = "delivered",
                                    rcpt = rcpt.address,
                                    mx = &params.hostname,
                                    response = %status,
                                );

                                rcpt.status = status;
                                rcpt.flags |= RCPT_STATUS_CHANGED;
                                total_completed += 1;
                            }
                        } else {
                            tracing::info!(
                                parent: params.span,
                                context = "message",
                                event = "rejected",
                                mx = &params.hostname,
                                reason = %response,
                            );

                            quit(smtp_client).await;
                            return Status::from_smtp_error(
                                params.hostname,
                                bdat_cmd.as_deref().unwrap_or("DATA"),
                                mail_send::Error::UnexpectedReply(response),
                            );
                        }
                    }
                    Err(status) => {
                        tracing::info!(
                            parent: params.span,
                            context = "message",
                            event = "failed",
                            mx = &params.hostname,
                            reason = %status,
                        );

                        quit(smtp_client).await;
                        return status;
                    }
                }
            } else {
                // Handle LMTP responses
                match read_lmtp_data_respone(
                    &mut smtp_client,
                    params.hostname,
                    accepted_rcpts.len(),
                )
                .await
                {
                    Ok(responses) => {
                        for ((rcpt, _), response) in accepted_rcpts.into_iter().zip(responses) {
                            rcpt.flags |= RCPT_STATUS_CHANGED;
                            rcpt.status = match response.severity() {
                                Severity::PositiveCompletion => {
                                    tracing::info!(
                                        parent: params.span,
                                        context = "rcpt",
                                        event = "delivered",
                                        rcpt = rcpt.address,
                                        mx = &params.hostname,
                                        response = %response,
                                    );

                                    total_completed += 1;
                                    Status::Completed(HostResponse {
                                        hostname: params.hostname.to_string(),
                                        response,
                                    })
                                }
                                severity => {
                                    tracing::info!(
                                        parent: params.span,
                                        context = "rcpt",
                                        event = "rejected",
                                        rcpt = rcpt.address,
                                        mx = &params.hostname,
                                        reason = %response,
                                    );

                                    let response = HostResponse {
                                        hostname: ErrorDetails {
                                            entity: params.hostname.to_string(),
                                            details: bdat_cmd
                                                .as_deref()
                                                .unwrap_or("DATA")
                                                .to_string(),
                                        },
                                        response,
                                    };
                                    if severity == Severity::PermanentNegativeCompletion {
                                        total_completed += 1;
                                        Status::PermanentFailure(response)
                                    } else {
                                        Status::TemporaryFailure(response)
                                    }
                                }
                            };
                        }
                    }
                    Err(status) => {
                        tracing::info!(
                            parent: params.span,
                            context = "message",
                            event = "rejected",
                            mx = &params.hostname,
                            reason = %status,
                        );

                        quit(smtp_client).await;
                        return status;
                    }
                }
            }
        }

        quit(smtp_client).await;
        if total_completed == total_rcpt {
            Status::Completed(())
        } else {
            Status::Scheduled
        }
    }

    fn build_mail_from(&self, capabilities: &EhloResponse<String>) -> String {
        let mut mail_from = String::with_capacity(self.return_path.len() + 60);
        let _ = write!(mail_from, "MAIL FROM:<{}>", self.return_path);
        if capabilities.has_capability(EXT_SIZE) {
            let _ = write!(mail_from, " SIZE={}", self.size);
        }
        if self.has_flag(MAIL_REQUIRETLS) & capabilities.has_capability(EXT_REQUIRE_TLS) {
            mail_from.push_str(" REQUIRETLS");
        }
        if self.has_flag(MAIL_SMTPUTF8) & capabilities.has_capability(EXT_SMTP_UTF8) {
            mail_from.push_str(" SMTPUTF8");
        }
        if capabilities.has_capability(EXT_DSN) {
            if self.has_flag(MAIL_RET_FULL) {
                mail_from.push_str(" RET=FULL");
            } else if self.has_flag(MAIL_RET_HDRS) {
                mail_from.push_str(" RET=HDRS");
            }
            if let Some(env_id) = &self.env_id {
                let _ = write!(mail_from, " ENVID={env_id}");
            }
        }

        mail_from.push_str("\r\n");
        mail_from
    }

    fn build_rcpt_to(&self, rcpt: &Recipient, capabilities: &EhloResponse<String>) -> String {
        let mut rcpt_to = String::with_capacity(rcpt.address.len() + 60);
        let _ = write!(rcpt_to, "RCPT TO:<{}>", rcpt.address);
        if capabilities.has_capability(EXT_DSN) {
            if rcpt.has_flag(RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY) {
                rcpt_to.push_str(" NOTIFY=");
                let mut add_comma = if rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                    rcpt_to.push_str("SUCCESS");
                    true
                } else {
                    false
                };
                if rcpt.has_flag(RCPT_NOTIFY_DELAY) {
                    if add_comma {
                        rcpt_to.push(',');
                    } else {
                        add_comma = true;
                    }
                    rcpt_to.push_str("DELAY");
                }
                if rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                    if add_comma {
                        rcpt_to.push(',');
                    }
                    rcpt_to.push_str("FAILURE");
                }
            } else if rcpt.has_flag(RCPT_NOTIFY_NEVER) {
                rcpt_to.push_str(" NOTIFY=NEVER");
            }
        }
        rcpt_to.push_str("\r\n");
        rcpt_to
    }

    #[inline(always)]
    pub fn has_flag(&self, flag: u64) -> bool {
        (self.flags & flag) != 0
    }
}

impl Recipient {
    #[inline(always)]
    pub fn has_flag(&self, flag: u64) -> bool {
        (self.flags & flag) != 0
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

pub async fn try_start_tls(
    mut smtp_client: SmtpClient<TcpStream>,
    tls_connector: &TlsConnector,
    hostname: &str,
    capabilities: &EhloResponse<String>,
) -> StartTlsResult {
    if capabilities.has_capability(EXT_START_TLS) {
        match smtp_client.cmd("STARTTLS\r\n").await {
            Ok(response) => {
                if response.code() == 220 {
                    match smtp_client.into_tls(tls_connector, hostname).await {
                        Ok(smtp_client) => StartTlsResult::Success { smtp_client },
                        Err(error) => StartTlsResult::Error { error },
                    }
                } else {
                    StartTlsResult::Unavailable {
                        response: response.into(),
                        smtp_client,
                    }
                }
            }
            Err(error) => StartTlsResult::Error { error },
        }
    } else {
        StartTlsResult::Unavailable {
            smtp_client,
            response: None,
        }
    }
}

pub async fn read_greeting<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    hostname: &str,
) -> Result<(), Status<(), Error>> {
    tokio::time::timeout(smtp_client.timeout, smtp_client.read())
        .await
        .map_err(|_| Status::timeout(hostname, "reading greeting"))?
        .and_then(|r| r.assert_code(220))
        .map_err(|err| Status::from_smtp_error(hostname, "", err))
}

pub async fn read_smtp_data_response<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    hostname: &str,
    bdat_cmd: &Option<String>,
) -> Result<Response<String>, Status<(), Error>> {
    tokio::time::timeout(smtp_client.timeout, smtp_client.read())
        .await
        .map_err(|_| Status::timeout(hostname, "reading SMTP DATA response"))?
        .map_err(|err| {
            Status::from_smtp_error(hostname, bdat_cmd.as_deref().unwrap_or("DATA"), err)
        })
}

pub async fn read_lmtp_data_respone<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    hostname: &str,
    num_responses: usize,
) -> Result<Vec<Response<String>>, Status<(), Error>> {
    tokio::time::timeout(smtp_client.timeout, async {
        smtp_client.read_many(num_responses).await
    })
    .await
    .map_err(|_| Status::timeout(hostname, "reading LMTP DATA responses"))?
    .map_err(|err| Status::from_smtp_error(hostname, "", err))
}

pub async fn write_chunks<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    chunks: &[&[u8]],
) -> Result<(), mail_send::Error> {
    for chunk in chunks {
        smtp_client
            .stream
            .write_all(chunk)
            .await
            .map_err(mail_send::Error::from)?;
    }
    smtp_client
        .stream
        .flush()
        .await
        .map_err(mail_send::Error::from)
}

pub async fn send_message<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
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
                write_chunks(smtp_client, &[bdat_cmd.as_bytes(), &raw_message]).await
            } else {
                write_chunks(smtp_client, &[b"DATA\r\n"]).await?;
                smtp_client.read().await?.assert_code(354)?;
                smtp_client
                    .write_message(&raw_message)
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
            tracing::error!(parent: params.span,
            context = "queue",
            event = "error",
            "BlobHash {:?} does not exist.",
            message.blob_hash,
            );
            Err(Status::TemporaryFailure(Error::Io(
                "Queue system error.".to_string(),
            )))
        }
        Err(err) => {
            tracing::error!(parent: params.span,
                context = "queue", 
                event = "error", 
                "Failed to fetch blobId {:?}: {}", 
                message.blob_hash,
                err);
            Err(Status::TemporaryFailure(Error::Io(
                "Queue system error.".to_string(),
            )))
        }
    }
}

pub async fn say_helo<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    params: &SessionParams<'_>,
) -> Result<EhloResponse<String>, Status<(), Error>> {
    let cmd = if params.is_smtp {
        format!("EHLO {}\r\n", params.local_hostname)
    } else {
        format!("LHLO {}\r\n", params.local_hostname)
    };
    tokio::time::timeout(params.timeout_ehlo, async {
        smtp_client.stream.write_all(cmd.as_bytes()).await?;
        smtp_client.stream.flush().await?;
        smtp_client.read_ehlo().await
    })
    .await
    .map_err(|_| Status::timeout(params.hostname, "reading EHLO response"))?
    .map_err(|err| Status::from_smtp_error(params.hostname, &cmd, err))
}

pub async fn quit<T: AsyncRead + AsyncWrite + Unpin>(mut smtp_client: SmtpClient<T>) {
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        if smtp_client.stream.write_all(b"QUIT\r\n").await.is_ok()
            && smtp_client.stream.flush().await.is_ok()
        {
            let mut buf = [0u8; 128];
            let _ = smtp_client.stream.read(&mut buf).await;
        }
    })
    .await;
}

impl TlsStrategy {
    #[inline(always)]
    pub fn try_dane(&self) -> bool {
        matches!(
            self.dane,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn try_start_tls(&self) -> bool {
        matches!(
            self.tls,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn is_dane_required(&self) -> bool {
        matches!(self.dane, RequireOptional::Require)
    }

    #[inline(always)]
    pub fn try_mta_sts(&self) -> bool {
        matches!(
            self.mta_sts,
            RequireOptional::Require | RequireOptional::Optional
        )
    }

    #[inline(always)]
    pub fn is_mta_sts_required(&self) -> bool {
        matches!(self.mta_sts, RequireOptional::Require)
    }

    #[inline(always)]
    pub fn is_tls_required(&self) -> bool {
        matches!(self.tls, RequireOptional::Require)
            || self.is_dane_required()
            || self.is_mta_sts_required()
    }
}
