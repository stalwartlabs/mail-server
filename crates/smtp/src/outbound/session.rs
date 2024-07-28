/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::RequireOptional;
use mail_send::{smtp::AssertReply, Credentials};
use smtp_proto::{
    EhloResponse, Severity, EXT_CHUNKING, EXT_DSN, EXT_REQUIRE_TLS, EXT_SIZE, EXT_SMTP_UTF8,
    MAIL_REQUIRETLS, MAIL_RET_FULL, MAIL_RET_HDRS, MAIL_SMTPUTF8, RCPT_NOTIFY_DELAY,
    RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use std::time::Duration;
use std::{fmt::Write, time::Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use trc::DeliveryEvent;

use crate::{
    core::SMTP,
    queue::{ErrorDetails, HostResponse, RCPT_STATUS_CHANGED},
};

use crate::queue::{Error, Message, Recipient, Status};

use super::{client::SmtpClient, TlsStrategy};

pub struct SessionParams<'x> {
    pub core: &'x SMTP,
    pub hostname: &'x str,
    pub credentials: Option<&'x Credentials<String>>,
    pub is_smtp: bool,
    pub local_hostname: &'x str,
    pub timeout_ehlo: Duration,
    pub timeout_mail: Duration,
    pub timeout_rcpt: Duration,
    pub timeout_data: Duration,
    pub session_id: u64,
}

impl Message {
    pub async fn deliver<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut smtp_client: SmtpClient<T>,
        recipients: impl Iterator<Item = &mut Recipient>,
        params: SessionParams<'_>,
    ) -> Status<(), Error> {
        // Obtain capabilities
        let time = Instant::now();
        let capabilities = match smtp_client.say_helo(&params).await {
            Ok(capabilities) => {
                trc::event!(
                    Delivery(DeliveryEvent::Ehlo),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    Details = capabilities.capabilities(),
                    Elapsed = time.elapsed(),
                );

                capabilities
            }
            Err(status) => {
                trc::event!(
                    Delivery(DeliveryEvent::EhloRejected),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    Reason = status.to_string(),
                    Elapsed = time.elapsed(),
                );
                smtp_client.quit().await;
                return status;
            }
        };

        // Authenticate
        if let Some(credentials) = params.credentials {
            let time = Instant::now();
            if let Err(err) = smtp_client.authenticate(credentials, &capabilities).await {
                trc::event!(
                    Delivery(DeliveryEvent::AuthFailed),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    Reason = err.to_string(),
                    Elapsed = time.elapsed(),
                );

                smtp_client.quit().await;
                return Status::from_smtp_error(params.hostname, "AUTH ...", err);
            }

            trc::event!(
                Delivery(DeliveryEvent::Auth),
                SpanId = params.session_id,
                Hostname = params.hostname.to_string(),
                Elapsed = time.elapsed(),
            );

            // Refresh capabilities
            // Disabled as some SMTP servers deauthenticate after EHLO
            /*capabilities = match say_helo(&mut smtp_client, &params).await {
                Ok(capabilities) => capabilities,
                Err(status) => {
                    trc::event!(

                        context = "ehlo",
                        event = "rejected",
                        mx = &params.hostname,
                        reason = %status,
                    );
                    smtp_client.quit().await;
                    return status;
                }
            };*/
        }

        // MAIL FROM
        let time = Instant::now();
        smtp_client.timeout = params.timeout_mail;
        let cmd = self.build_mail_from(&capabilities);
        if let Err(err) = smtp_client
            .cmd(cmd.as_bytes())
            .await
            .and_then(|r| r.assert_positive_completion())
        {
            trc::event!(
                Delivery(DeliveryEvent::MailFromRejected),
                SpanId = params.session_id,
                Hostname = params.hostname.to_string(),
                Reason = err.to_string(),
                Elapsed = time.elapsed(),
            );

            smtp_client.quit().await;
            return Status::from_smtp_error(params.hostname, &cmd, err);
        }

        trc::event!(
            Delivery(DeliveryEvent::MailFrom),
            SpanId = params.session_id,
            Hostname = params.hostname.to_string(),
            From = self.return_path.to_string(),
            Elapsed = time.elapsed(),
        );

        // RCPT TO
        let mut total_rcpt = 0;
        let mut total_completed = 0;
        let mut accepted_rcpts = Vec::new();
        smtp_client.timeout = params.timeout_rcpt;
        for rcpt in recipients {
            let time = Instant::now();
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
                        trc::event!(
                            Delivery(DeliveryEvent::RcptTo),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            To = rcpt.address.to_string(),
                            Details = response.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        accepted_rcpts.push((
                            rcpt,
                            Status::Completed(HostResponse {
                                hostname: params.hostname.to_string(),
                                response,
                            }),
                        ));
                    }
                    severity => {
                        trc::event!(
                            Delivery(DeliveryEvent::RcptToRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            To = rcpt.address.to_string(),
                            Reason = response.to_string(),
                            Elapsed = time.elapsed(),
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
                    trc::event!(
                        Delivery(DeliveryEvent::RcptToFailed),
                        SpanId = params.session_id,
                        Hostname = params.hostname.to_string(),
                        To = rcpt.address.to_string(),
                        Reason = err.to_string(),
                        Elapsed = time.elapsed(),
                    );

                    // Something went wrong, abort.
                    smtp_client.quit().await;
                    return Status::from_smtp_error(params.hostname, "", err);
                }
            }
        }

        // Send message
        if !accepted_rcpts.is_empty() {
            let time = Instant::now();
            let bdat_cmd = capabilities
                .has_capability(EXT_CHUNKING)
                .then(|| format!("BDAT {} LAST\r\n", self.size));

            if let Err(status) = smtp_client.send_message(self, &bdat_cmd, &params).await {
                trc::event!(
                    Delivery(DeliveryEvent::MessageRejected),
                    SpanId = params.session_id,
                    Hostname = params.hostname.to_string(),
                    Reason = status.to_string(),
                    Elapsed = time.elapsed(),
                );

                smtp_client.quit().await;
                return status;
            }

            if params.is_smtp {
                // Handle SMTP response
                match smtp_client
                    .read_smtp_data_response(params.hostname, &bdat_cmd)
                    .await
                {
                    Ok(response) => {
                        // Mark recipients as delivered
                        if response.code() == 250 {
                            for (rcpt, status) in accepted_rcpts {
                                trc::event!(
                                    Delivery(DeliveryEvent::Delivered),
                                    SpanId = params.session_id,
                                    Hostname = params.hostname.to_string(),
                                    To = rcpt.address.to_string(),
                                    Details = status.to_string(),
                                    Elapsed = time.elapsed(),
                                );

                                rcpt.status = status;
                                rcpt.flags |= RCPT_STATUS_CHANGED;
                                total_completed += 1;
                            }
                        } else {
                            trc::event!(
                                Delivery(DeliveryEvent::MessageRejected),
                                SpanId = params.session_id,
                                Hostname = params.hostname.to_string(),
                                Reason = response.to_string(),
                                Elapsed = time.elapsed(),
                            );

                            smtp_client.quit().await;
                            return Status::from_smtp_error(
                                params.hostname,
                                bdat_cmd.as_deref().unwrap_or("DATA"),
                                mail_send::Error::UnexpectedReply(response),
                            );
                        }
                    }
                    Err(status) => {
                        trc::event!(
                            Delivery(DeliveryEvent::MessageRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            Reason = status.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        smtp_client.quit().await;
                        return status;
                    }
                }
            } else {
                // Handle LMTP responses
                match smtp_client
                    .read_lmtp_data_response(params.hostname, accepted_rcpts.len())
                    .await
                {
                    Ok(responses) => {
                        for ((rcpt, _), response) in accepted_rcpts.into_iter().zip(responses) {
                            rcpt.flags |= RCPT_STATUS_CHANGED;
                            rcpt.status = match response.severity() {
                                Severity::PositiveCompletion => {
                                    trc::event!(
                                        Delivery(DeliveryEvent::Delivered),
                                        SpanId = params.session_id,
                                        Hostname = params.hostname.to_string(),
                                        To = rcpt.address.to_string(),
                                        Details = response.to_string(),
                                        Elapsed = time.elapsed(),
                                    );

                                    total_completed += 1;
                                    Status::Completed(HostResponse {
                                        hostname: params.hostname.to_string(),
                                        response,
                                    })
                                }
                                severity => {
                                    trc::event!(
                                        Delivery(DeliveryEvent::RcptToRejected),
                                        SpanId = params.session_id,
                                        Hostname = params.hostname.to_string(),
                                        To = rcpt.address.to_string(),
                                        Reason = response.to_string(),
                                        Elapsed = time.elapsed(),
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
                        trc::event!(
                            Delivery(DeliveryEvent::MessageRejected),
                            SpanId = params.session_id,
                            Hostname = params.hostname.to_string(),
                            Reason = status.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        smtp_client.quit().await;
                        return status;
                    }
                }
            }
        }

        smtp_client.quit().await;
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
