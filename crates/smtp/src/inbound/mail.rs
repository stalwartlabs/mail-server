/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant, SystemTime};

use common::{config::smtp::session::Stage, listener::SessionStream, scripts::ScriptModification};
use mail_auth::{IprevOutput, IprevResult, SpfOutput, SpfResult};
use smtp_proto::{MailFrom, MtPriority, MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_REQUIRETLS};
use trc::SmtpEvent;
use utils::config::Rate;

use crate::{
    core::{Session, SessionAddress},
    queue::DomainPart,
    scripts::ScriptResult,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_mail_from(&mut self, from: MailFrom<String>) -> Result<(), ()> {
        if self.data.helo_domain.is_empty()
            && (self.params.ehlo_require
                || self.params.spf_ehlo.verify()
                || self.params.spf_mail_from.verify())
        {
            trc::event!(
                Smtp(SmtpEvent::DidNotSayEhlo),
                SpanId = self.data.session_id,
            );

            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            trc::event!(
                Smtp(SmtpEvent::MultipleMailFrom),
                SpanId = self.data.session_id,
            );

            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        } else if self.params.auth_require && self.data.authenticated_as.is_empty() {
            trc::event!(
                Smtp(SmtpEvent::MailFromUnauthenticated),
                SpanId = self.data.session_id,
            );

            return self
                .write(b"503 5.5.1 You must authenticate first.\r\n")
                .await;
        } else if self.data.iprev.is_none() && self.params.iprev.verify() {
            let time = Instant::now();
            let iprev = self
                .core
                .core
                .smtp
                .resolvers
                .dns
                .verify_iprev(self.data.remote_ip)
                .await;

            trc::event!(
                Smtp(if matches!(iprev.result(), IprevResult::Pass) {
                    SmtpEvent::IprevPass
                } else {
                    SmtpEvent::IprevFail
                }),
                SpanId = self.data.session_id,
                Domain = self.data.helo_domain.clone(),
                Result = trc::Event::from(&iprev),
                Elapsed = time.elapsed(),
            );

            self.data.iprev = iprev.into();
        }

        // In strict mode reject messages from hosts that fail the reverse DNS lookup check
        if self.params.iprev.is_strict()
            && !matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::Pass,
                    ..
                })
            )
        {
            let message = if matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::TempError(_),
                    ..
                })
            ) {
                &b"451 4.7.25 Temporary error validating reverse DNS.\r\n"[..]
            } else {
                &b"550 5.7.25 Reverse DNS validation failed.\r\n"[..]
            };

            return self.write(message).await;
        }

        let (address, address_lcase, domain) = if !from.address.is_empty() {
            let address_lcase = from.address.to_lowercase();
            let domain = address_lcase.domain_part().to_string();
            (from.address, address_lcase, domain)
        } else {
            (String::new(), String::new(), String::new())
        };

        let has_dsn = from.env_id.is_some();
        self.data.mail_from = SessionAddress {
            address,
            address_lcase,
            domain,
            flags: from.flags,
            dsn_info: from.env_id,
        }
        .into();

        // Check whether the address is allowed
        if !self
            .core
            .core
            .eval_if::<bool, _>(
                &self.core.core.smtp.session.mail.is_allowed,
                self,
                self.data.session_id,
            )
            .await
            .unwrap_or(true)
        {
            let mail_from = self.data.mail_from.take().unwrap();
            trc::event!(
                Smtp(SmtpEvent::MailFromNotAllowed),
                From = mail_from.address_lcase,
                SpanId = self.data.session_id,
            );
            return self
                .write(b"550 5.7.1 Sender address not allowed.\r\n")
                .await;
        }

        // Sieve filtering
        if let Some((script, script_id)) = self
            .core
            .core
            .eval_if::<String, _>(
                &self.core.core.smtp.session.mail.script,
                self,
                self.data.session_id,
            )
            .await
            .and_then(|name| {
                self.core
                    .core
                    .get_trusted_sieve_script(&name, self.data.session_id)
                    .map(|s| (s, name))
            })
        {
            match self
                .run_script(
                    script_id,
                    script.clone(),
                    self.build_script_parameters("mail"),
                )
                .await
            {
                ScriptResult::Accept { modifications } => {
                    if !modifications.is_empty() {
                        for modification in modifications {
                            if let ScriptModification::SetEnvelope { name, value } = modification {
                                self.data.apply_envelope_modification(name, value);
                            }
                        }
                    }
                }
                ScriptResult::Reject(message) => {
                    self.data.mail_from = None;
                    return self.write(message.as_bytes()).await;
                }
                _ => (),
            }
        }

        // Milter filtering
        if let Err(message) = self.run_milters(Stage::Mail, None).await {
            self.data.mail_from = None;
            return self.write(message.message.as_bytes()).await;
        }

        // MTAHook filtering
        if let Err(message) = self.run_mta_hooks(Stage::Mail, None, None).await {
            self.data.mail_from = None;
            return self.write(message.message.as_bytes()).await;
        }

        // Address rewriting
        if let Some(new_address) = self
            .core
            .core
            .eval_if::<String, _>(
                &self.core.core.smtp.session.mail.rewrite,
                self,
                self.data.session_id,
            )
            .await
        {
            let mail_from = self.data.mail_from.as_mut().unwrap();

            trc::event!(
                Smtp(SmtpEvent::MailFromRewritten),
                SpanId = self.data.session_id,
                Details = mail_from.address_lcase.clone(),
                From = new_address.clone(),
            );

            if new_address.contains('@') {
                mail_from.address_lcase = new_address.to_lowercase();
                mail_from.domain = mail_from.address_lcase.domain_part().to_string();
                mail_from.address = new_address;
            } else if new_address.is_empty() {
                mail_from.address_lcase.clear();
                mail_from.domain.clear();
                mail_from.address.clear();
            }
        }

        // Make sure that the authenticated user is allowed to send from this address
        if !self.data.authenticated_as.is_empty() && self.params.auth_match_sender {
            let address_lcase = self.data.mail_from.as_ref().unwrap().address_lcase.as_str();
            if self.data.authenticated_as != address_lcase
                && !self.data.authenticated_emails.iter().any(|e| {
                    e == address_lcase || (e.starts_with('@') && address_lcase.ends_with(e))
                })
            {
                trc::event!(
                    Smtp(SmtpEvent::MailFromUnauthorized),
                    SpanId = self.data.session_id,
                    From = address_lcase.to_string(),
                    Details = [trc::Value::String(self.data.authenticated_as.to_string())]
                        .into_iter()
                        .chain(
                            self.data
                                .authenticated_emails
                                .iter()
                                .map(|e| trc::Value::String(e.to_string()))
                        )
                        .collect::<Vec<_>>()
                );
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 You are not allowed to send from this address.\r\n")
                    .await;
            }
        }

        // Validate parameters
        let config = &self.core.core.smtp.session.extensions;
        let config_data = &self.core.core.smtp.session.data;
        if (from.flags & MAIL_REQUIRETLS) != 0
            && !self
                .core
                .core
                .eval_if(&config.requiretls, self, self.data.session_id)
                .await
                .unwrap_or(false)
        {
            trc::event!(
                Smtp(SmtpEvent::RequireTlsDisabled),
                SpanId = self.data.session_id,
            );
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 REQUIRETLS has been disabled.\r\n")
                .await;
        }
        if (from.flags & (MAIL_BY_NOTIFY | MAIL_BY_RETURN)) != 0 {
            if let Some(duration) = self
                .core
                .core
                .eval_if::<Duration, _>(&config.deliver_by, self, self.data.session_id)
                .await
            {
                if from.by.checked_abs().unwrap_or(0) as u64 <= duration.as_secs()
                    && (from.by.is_positive() || (from.flags & MAIL_BY_NOTIFY) != 0)
                {
                    self.data.delivery_by = from.by;
                } else {
                    self.data.mail_from = None;

                    trc::event!(
                        Smtp(SmtpEvent::DeliverByInvalid),
                        SpanId = self.data.session_id,
                        Details = from.by,
                    );

                    return self
                        .write(
                            format!(
                                "501 5.5.4 BY parameter exceeds maximum of {} seconds.\r\n",
                                duration.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            } else {
                trc::event!(
                    Smtp(SmtpEvent::DeliverByDisabled),
                    SpanId = self.data.session_id,
                );
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 DELIVERBY extension has been disabled.\r\n")
                    .await;
            }
        }
        if from.mt_priority != 0 {
            if self
                .core
                .core
                .eval_if::<MtPriority, _>(&config.mt_priority, self, self.data.session_id)
                .await
                .is_some()
            {
                if (-6..6).contains(&from.mt_priority) {
                    self.data.priority = from.mt_priority as i16;
                } else {
                    trc::event!(
                        Smtp(SmtpEvent::MtPriorityInvalid),
                        SpanId = self.data.session_id,
                        Details = from.mt_priority,
                    );
                    self.data.mail_from = None;
                    return self.write(b"501 5.5.4 Invalid priority value.\r\n").await;
                }
            } else {
                trc::event!(
                    Smtp(SmtpEvent::MtPriorityDisabled),
                    SpanId = self.data.session_id,
                );
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 MT-PRIORITY extension has been disabled.\r\n")
                    .await;
            }
        }
        if from.size > 0
            && from.size
                > self
                    .core
                    .core
                    .eval_if(&config_data.max_message_size, self, self.data.session_id)
                    .await
                    .unwrap_or(25 * 1024 * 1024)
        {
            trc::event!(
                Smtp(SmtpEvent::MessageTooLarge),
                SpanId = self.data.session_id,
                Size = from.size,
            );

            self.data.mail_from = None;
            return self
                .write(b"552 5.3.4 Message too big for system.\r\n")
                .await;
        }
        if from.hold_for != 0 || from.hold_until != 0 {
            if let Some(max_hold) = self
                .core
                .core
                .eval_if::<Duration, _>(&config.future_release, self, self.data.session_id)
                .await
            {
                let max_hold = max_hold.as_secs();
                let hold_for = if from.hold_for != 0 {
                    from.hold_for
                } else {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    if from.hold_until > now {
                        from.hold_until - now
                    } else {
                        0
                    }
                };
                if hold_for <= max_hold {
                    self.data.future_release = hold_for;
                } else {
                    trc::event!(
                        Smtp(SmtpEvent::FutureReleaseInvalid),
                        SpanId = self.data.session_id,
                        Details = hold_for,
                    );
                    self.data.mail_from = None;
                    return self
                        .write(
                            format!(
                                "501 5.5.4 Requested hold time exceeds maximum of {max_hold} seconds.\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            } else {
                trc::event!(
                    Smtp(SmtpEvent::FutureReleaseDisabled),
                    SpanId = self.data.session_id,
                );
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 FUTURERELEASE extension has been disabled.\r\n")
                    .await;
            }
        }
        if has_dsn
            && !self
                .core
                .core
                .eval_if(&config.dsn, self, self.data.session_id)
                .await
                .unwrap_or(false)
        {
            trc::event!(Smtp(SmtpEvent::DsnDisabled), SpanId = self.data.session_id,);
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        if self.is_allowed().await {
            // Verify SPF
            if self.params.spf_mail_from.verify() {
                let time = Instant::now();
                let mail_from = self.data.mail_from.as_ref().unwrap();
                let spf_output = if !mail_from.address.is_empty() {
                    self.core
                        .core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &mail_from.domain,
                            &self.data.helo_domain,
                            &self.hostname,
                            &mail_from.address_lcase,
                        )
                        .await
                } else {
                    self.core
                        .core
                        .smtp
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &self.data.helo_domain,
                            &self.data.helo_domain,
                            &self.hostname,
                            &format!("postmaster@{}", self.data.helo_domain),
                        )
                        .await
                };

                trc::event!(
                    Smtp(if matches!(spf_output.result(), SpfResult::Pass) {
                        SmtpEvent::SpfFromPass
                    } else {
                        SmtpEvent::SpfFromFail
                    }),
                    SpanId = self.data.session_id,
                    Domain = self.data.helo_domain.clone(),
                    From = if !mail_from.address.is_empty() {
                        mail_from.address.as_str()
                    } else {
                        "<>"
                    }
                    .to_string(),
                    Result = trc::Event::from(&spf_output),
                    Elapsed = time.elapsed(),
                );

                if self
                    .handle_spf(&spf_output, self.params.spf_mail_from.is_strict())
                    .await?
                {
                    self.data.spf_mail_from = spf_output.into();
                } else {
                    self.data.mail_from = None;
                    return Ok(());
                }
            }

            trc::event!(
                Smtp(SmtpEvent::MailFrom),
                SpanId = self.data.session_id,
                From = self.data.mail_from.as_ref().unwrap().address_lcase.clone(),
            );

            self.eval_rcpt_params().await;
            self.write(b"250 2.1.0 OK\r\n").await
        } else {
            trc::event!(
                Smtp(SmtpEvent::RateLimitExceeded),
                SpanId = self.data.session_id,
                From = self.data.mail_from.as_ref().unwrap().address_lcase.clone(),
            );

            self.data.mail_from = None;
            self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await
        }
    }

    pub async fn handle_spf(&mut self, spf_output: &SpfOutput, strict: bool) -> Result<bool, ()> {
        let result = match spf_output.result() {
            SpfResult::Pass => true,
            SpfResult::TempError if strict => {
                self.write(b"451 4.7.24 Temporary SPF validation error.\r\n")
                    .await?;
                false
            }
            result => {
                if strict {
                    self.write(
                        format!("550 5.7.23 SPF validation failed, status: {result}.\r\n")
                            .as_bytes(),
                    )
                    .await?;
                    false
                } else {
                    true
                }
            }
        };

        // Send report
        if let (Some(recipient), Some(rate)) = (
            spf_output.report_address(),
            self.core
                .core
                .eval_if::<Rate, _>(
                    &self.core.core.smtp.report.spf.send,
                    self,
                    self.data.session_id,
                )
                .await,
        ) {
            self.send_spf_report(recipient, &rate, !result, spf_output)
                .await;
        }

        Ok(result)
    }
}
