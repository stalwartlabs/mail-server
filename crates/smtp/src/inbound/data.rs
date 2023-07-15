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

use std::{
    borrow::Cow,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use mail_auth::{
    common::headers::HeaderWriter, dmarc, AuthenticatedMessage, AuthenticationResults, DkimResult,
    DmarcResult, ReceivedSpf,
};
use mail_builder::headers::{date::Date, message_id::generate_message_id_header};
use smtp_proto::{
    MAIL_BY_RETURN, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    process::Command,
};

use crate::{
    config::DNSBL_FROM,
    core::{scripts::ScriptResult, Session, SessionAddress, State},
    queue::{self, DomainPart, Message, SimpleEnvelope},
    reporting::analysis::AnalyzeReport,
};

use super::IsTls;

impl<T: AsyncWrite + AsyncRead + IsTls + Unpin> Session<T> {
    pub async fn queue_message(&mut self) -> Cow<'static, [u8]> {
        // Authenticate message
        let raw_message = Arc::new(std::mem::take(&mut self.data.message));
        let auth_message = if let Some(auth_message) = AuthenticatedMessage::parse(&raw_message) {
            auth_message
        } else {
            tracing::info!(parent: &self.span,
                    context = "data",
                    event = "parse-failed",
                    size = raw_message.len());

            return (&b"550 5.7.7 Failed to parse message.\r\n"[..]).into();
        };

        // Validate DNSBL
        let from = auth_message.from();
        let from_domain = from.domain_part();
        if !from_domain.is_empty()
            && !self
                .is_domain_dnsbl_allowed(from_domain, "from", DNSBL_FROM)
                .await
        {
            return self.reset_dnsbl_error().unwrap().into();
        }

        // Loop detection
        let dc = &self.core.session.config.data;
        let ac = &self.core.mail_auth;
        let rc = &self.core.report.config;
        if auth_message.received_headers_count() > *dc.max_received_headers.eval(self).await {
            tracing::info!(parent: &self.span,
                context = "data",
                event = "loop-detected",
                return_path = self.data.mail_from.as_ref().unwrap().address,
                from = auth_message.from(),
                received_headers = auth_message.received_headers_count());
            return (&b"450 4.4.6 Too many Received headers. Possible loop detected.\r\n"[..])
                .into();
        }

        // Verify DKIM
        let dkim = *ac.dkim.verify.eval(self).await;
        let dmarc = *ac.dmarc.verify.eval(self).await;
        let dkim_output = if dkim.verify() || dmarc.verify() {
            let dkim_output = self.core.resolvers.dns.verify_dkim(&auth_message).await;
            let rejected = dkim.is_strict()
                && !dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::Pass));

            // Send reports for failed signatures
            if let Some(rate) = rc.dkim.send.eval(self).await {
                for output in &dkim_output {
                    if let Some(rcpt) = output.failure_report_addr() {
                        self.send_dkim_report(rcpt, &auth_message, rate, rejected, output)
                            .await;
                    }
                }
            }

            if rejected {
                tracing::info!(parent: &self.span,
                    context = "dkim",
                    event = "failed",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = ?dkim_output.iter().map(|d| d.result().to_string()).collect::<Vec<_>>(),
                    "No passing DKIM signatures found.");

                // 'Strict' mode violates the advice of Section 6.1 of RFC6376
                return if dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                {
                    (&b"451 4.7.20 No passing DKIM signatures found.\r\n"[..]).into()
                } else {
                    (&b"550 5.7.20 No passing DKIM signatures found.\r\n"[..]).into()
                };
            } else {
                tracing::debug!(parent: &self.span,
                    context = "dkim",
                    event = "verify",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = ?dkim_output.iter().map(|d| d.result().to_string()).collect::<Vec<_>>());
            }
            dkim_output
        } else {
            vec![]
        };

        // Verify ARC
        let arc = *ac.arc.verify.eval(self).await;
        let arc_sealer = ac.arc.seal.eval(self).await;
        let arc_output = if arc.verify() || arc_sealer.is_some() {
            let arc_output = self.core.resolvers.dns.verify_arc(&auth_message).await;

            if arc.is_strict()
                && !matches!(arc_output.result(), DkimResult::Pass | DkimResult::None)
            {
                tracing::info!(parent: &self.span,
                    context = "arc",
                    event = "auth-failed",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = %arc_output.result(),
                    "ARC validation failed.");

                return if matches!(arc_output.result(), DkimResult::TempError(_)) {
                    (&b"451 4.7.29 ARC validation failed.\r\n"[..]).into()
                } else {
                    (&b"550 5.7.29 ARC validation failed.\r\n"[..]).into()
                };
            } else {
                tracing::debug!(parent: &self.span,
                    context = "arc",
                    event = "verify",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = %arc_output.result());
            }
            arc_output.into()
        } else {
            None
        };

        // Build authentication results header
        let mail_from = self.data.mail_from.as_ref().unwrap();
        let mut auth_results = AuthenticationResults::new(&self.instance.hostname);
        if !dkim_output.is_empty() {
            auth_results = auth_results.with_dkim_results(&dkim_output, auth_message.from())
        }
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            auth_results = auth_results.with_spf_ehlo_result(
                spf_ehlo,
                self.data.remote_ip,
                &self.data.helo_domain,
            );
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            auth_results = auth_results.with_spf_mailfrom_result(
                spf_mail_from,
                self.data.remote_ip,
                &mail_from.address,
                &self.data.helo_domain,
            );
        }
        if let Some(iprev) = &self.data.iprev {
            auth_results = auth_results.with_iprev_result(iprev, self.data.remote_ip);
        }

        // Verify DMARC
        match &self.data.spf_mail_from {
            Some(spf_output) if dmarc.verify() => {
                let dmarc_output = self
                    .core
                    .resolvers
                    .dns
                    .verify_dmarc(
                        &auth_message,
                        &dkim_output,
                        if !mail_from.domain.is_empty() {
                            &mail_from.domain
                        } else {
                            &self.data.helo_domain
                        },
                        spf_output,
                    )
                    .await;

                let rejected = dmarc.is_strict()
                    && dmarc_output.policy() == dmarc::Policy::Reject
                    && !(matches!(dmarc_output.spf_result(), DmarcResult::Pass)
                        || matches!(dmarc_output.dkim_result(), DmarcResult::Pass));
                let is_temp_fail = rejected
                    && matches!(dmarc_output.spf_result(), DmarcResult::TempError(_))
                    || matches!(dmarc_output.dkim_result(), DmarcResult::TempError(_));

                // Add to DMARC output to the Authentication-Results header
                auth_results = auth_results.with_dmarc_result(&dmarc_output);

                if !rejected {
                    tracing::debug!(parent: &self.span,
                    context = "dmarc",
                    event = "verify",
                    return_path = mail_from.address,
                    from = auth_message.from(),
                    dkim_result = %dmarc_output.dkim_result(),
                    spf_result = %dmarc_output.spf_result());
                } else {
                    tracing::info!(parent: &self.span,
                    context = "dmarc",
                    event = "auth-failed",
                    return_path = mail_from.address,
                    from = auth_message.from(),
                    dkim_result = %dmarc_output.dkim_result(),
                    spf_result = %dmarc_output.spf_result());
                }

                // Send DMARC report
                if dmarc_output.requested_reports() {
                    self.send_dmarc_report(
                        &auth_message,
                        &auth_results,
                        rejected,
                        dmarc_output,
                        &dkim_output,
                        &arc_output,
                    )
                    .await;
                }

                if rejected {
                    return if is_temp_fail {
                        (&b"451 4.7.1 Email temporarily rejected per DMARC policy.\r\n"[..]).into()
                    } else {
                        (&b"550 5.7.1 Email rejected per DMARC policy.\r\n"[..]).into()
                    };
                }
            }
            _ => (),
        }

        // Analyze reports
        if self.is_report() {
            self.core.analyze_report(raw_message.clone());
            if !rc.analysis.forward {
                self.data.messages_sent += 1;
                return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
            }
        }

        // Pipe message
        let mut edited_message = None;
        for pipe in &dc.pipe_commands {
            if let Some(command_) = pipe.command.eval(self).await {
                let piped_message = edited_message.as_ref().unwrap_or(&raw_message).clone();
                let timeout = *pipe.timeout.eval(self).await;

                let mut command = Command::new(command_);
                for argument in pipe.arguments.eval(self).await {
                    command.arg(argument);
                }
                match command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                {
                    Ok(mut child) => {
                        if let Some(mut stdin) = child.stdin.take() {
                            match tokio::time::timeout(timeout, stdin.write_all(&piped_message))
                                .await
                            {
                                Ok(Ok(_)) => {
                                    drop(stdin);
                                    match tokio::time::timeout(timeout, child.wait_with_output())
                                        .await
                                    {
                                        Ok(Ok(output)) => {
                                            if output.status.success()
                                                && !output.stdout.is_empty()
                                                && output.stdout[..] != piped_message[..]
                                            {
                                                edited_message = Arc::new(output.stdout).into();
                                            }

                                            tracing::debug!(parent: &self.span,
                                                context = "pipe",
                                                event = "success",
                                                command = command_,
                                                status = output.status.to_string());
                                        }
                                        Ok(Err(err)) => {
                                            tracing::warn!(parent: &self.span,
                                                context = "pipe",
                                                event = "exec-error",
                                                command = command_,
                                                reason = %err);
                                        }
                                        Err(_) => {
                                            tracing::warn!(parent: &self.span,
                                                context = "pipe",
                                                event = "timeout",
                                                command = command_);
                                        }
                                    }
                                }
                                Ok(Err(err)) => {
                                    tracing::warn!(parent: &self.span,
                                        context = "pipe",
                                        event = "write-error",
                                        command = command_,
                                        reason = %err);
                                }
                                Err(_) => {
                                    tracing::warn!(parent: &self.span,
                                        context = "pipe",
                                        event = "stdin-timeout",
                                        command = command_);
                                }
                            }
                        } else {
                            tracing::warn!(parent: &self.span,
                                context = "pipe",
                                event = "stdin-failed",
                                command = command_);
                        }
                    }
                    Err(err) => {
                        tracing::warn!(parent: &self.span,
                                context = "pipe",
                                event = "spawn-error",
                                command = command_,
                                reason = %err);
                    }
                }
            }
        }

        // Sieve filtering
        if let Some(script) = dc.script.eval(self).await {
            match self
                .run_script(
                    script.clone(),
                    Some(edited_message.as_ref().unwrap_or(&raw_message).clone()),
                )
                .await
            {
                ScriptResult::Accept => (),
                ScriptResult::Replace(new_message) => {
                    edited_message = Arc::new(new_message).into();
                }
                ScriptResult::Reject(message) => {
                    tracing::debug!(parent: &self.span,
                        context = "data",
                        event = "sieve-reject",
                        reason = message);

                    return message.into_bytes().into();
                }
                ScriptResult::Discard => {
                    return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
                }
            }
        }

        // Build message
        let mail_from = self.data.mail_from.clone().unwrap();
        let rcpt_to = std::mem::take(&mut self.data.rcpt_to);
        let mut message = self.build_message(mail_from, rcpt_to).await;

        // Add Received header
        let mut headers = Vec::with_capacity(64);
        if *dc.add_received.eval(self).await {
            self.write_received(&mut headers, message.id)
        }

        // Add authentication results header
        if *dc.add_auth_results.eval(self).await {
            auth_results.write_header(&mut headers);
        }

        // Add Received-SPF header
        if let Some(spf_output) = &self.data.spf_mail_from {
            if *dc.add_received_spf.eval(self).await {
                ReceivedSpf::new(
                    spf_output,
                    self.data.remote_ip,
                    &self.data.helo_domain,
                    &message.return_path,
                    &self.instance.hostname,
                )
                .write_header(&mut headers);
            }
        }

        // ARC Seal
        if let (Some(arc_sealer), Some(arc_output)) = (arc_sealer, &arc_output) {
            if !dkim_output.is_empty() && arc_output.can_be_sealed() {
                match arc_sealer.seal(&auth_message, &auth_results, arc_output) {
                    Ok(set) => {
                        set.write_header(&mut headers);
                    }
                    Err(err) => {
                        tracing::info!(parent: &self.span,
                            context = "arc",
                            event = "seal-failed",
                            return_path = message.return_path,
                            from = auth_message.from(),
                            "Failed to seal message: {}", err);
                    }
                }
            }
        }

        // Add any missing headers
        if !auth_message.has_date_header() && *dc.add_date.eval(self).await {
            headers.extend_from_slice(b"Date: ");
            headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        if !auth_message.has_message_id_header() && *dc.add_message_id.eval(self).await {
            headers.extend_from_slice(b"Message-ID: ");
            let _ = generate_message_id_header(&mut headers, &self.instance.hostname);
            headers.extend_from_slice(b"\r\n");
        }

        // Add Return-Path
        if *dc.add_return_path.eval(self).await {
            headers.extend_from_slice(b"Return-Path: <");
            headers.extend_from_slice(message.return_path.as_bytes());
            headers.extend_from_slice(b">\r\n");
        }

        // DKIM sign
        let raw_message = edited_message.unwrap_or(raw_message);
        for signer in ac.dkim.sign.eval(self).await.iter() {
            match signer.sign_chained(&[headers.as_ref(), &raw_message]) {
                Ok(signature) => {
                    signature.write_header(&mut headers);
                }
                Err(err) => {
                    tracing::info!(parent: &self.span,
                        context = "dkim",
                        event = "sign-failed",
                        return_path = message.return_path,
                        "Failed to sign message: {}", err);
                }
            }
        }

        // Update size
        message.size = raw_message.len() + headers.len();

        // Verify queue quota
        if self.core.queue.has_quota(&mut message).await {
            let queue_id = message.id;
            if self
                .core
                .queue
                .queue_message(message, Some(&headers), &raw_message, &self.span)
                .await
            {
                self.state = State::Accepted(queue_id);
                self.data.messages_sent += 1;
                (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into()
            } else {
                (b"451 4.3.5 Unable to accept message at this time.\r\n"[..]).into()
            }
        } else {
            tracing::warn!(
                parent: &self.span,
                context = "queue",
                event = "quota-exceeded",
                from = message.return_path,
                "Queue quota exceeded, rejecting message."
            );
            (b"452 4.3.1 Mail system full, try again later.\r\n"[..]).into()
        }
    }

    pub async fn build_message(
        &self,
        mail_from: SessionAddress,
        mut rcpt_to: Vec<SessionAddress>,
    ) -> Box<Message> {
        // Build message
        let mut message = Box::new(Message {
            id: self.core.queue.queue_id(),
            path: PathBuf::new(),
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(rcpt_to.len()),
            domains: Vec::with_capacity(3),
            flags: mail_from.flags,
            priority: self.data.priority,
            size: 0,
            env_id: mail_from.dsn_info,
            queue_refs: Vec::with_capacity(0),
        });

        // Add recipients
        let future_release = Duration::from_secs(self.data.future_release);
        rcpt_to.sort_unstable();
        for rcpt in rcpt_to {
            if message
                .domains
                .last()
                .map_or(true, |d| d.domain != rcpt.domain)
            {
                let envelope = SimpleEnvelope::new(message.as_ref(), &rcpt.domain);

                // Set next retry time
                let retry = if self.data.future_release == 0 {
                    queue::Schedule::now()
                } else {
                    queue::Schedule::later(future_release)
                };

                // Set expiration and notification times
                let config = &self.core.queue.config;
                let notify_intervals = config.notify.eval(&envelope).await;
                let (notify, expires) = if self.data.delivery_by == 0 {
                    (
                        queue::Schedule::later(future_release + *notify_intervals.first().unwrap()),
                        Instant::now() + future_release + *config.expire.eval(&envelope).await,
                    )
                } else if (message.flags & MAIL_BY_RETURN) != 0 {
                    (
                        queue::Schedule::later(future_release + *notify_intervals.first().unwrap()),
                        Instant::now() + Duration::from_secs(self.data.delivery_by as u64),
                    )
                } else {
                    let expire = *config.expire.eval(&envelope).await;
                    let expire_secs = expire.as_secs();
                    let notify = if self.data.delivery_by.is_positive() {
                        let notify_at = self.data.delivery_by as u64;
                        if expire_secs > notify_at {
                            Duration::from_secs(notify_at)
                        } else {
                            *notify_intervals.first().unwrap()
                        }
                    } else {
                        let notify_at = -self.data.delivery_by as u64;
                        if expire_secs > notify_at {
                            Duration::from_secs(expire_secs - notify_at)
                        } else {
                            *notify_intervals.first().unwrap()
                        }
                    };
                    let mut notify = queue::Schedule::later(future_release + notify);
                    notify.inner = (notify_intervals.len() - 1) as u32; // Disable further notification attempts

                    (notify, Instant::now() + expire)
                };

                message.domains.push(queue::Domain {
                    retry,
                    notify,
                    expires,
                    status: queue::Status::Scheduled,
                    domain: rcpt.domain,
                    changed: false,
                });
            }

            message.recipients.push(queue::Recipient {
                address: rcpt.address,
                address_lcase: rcpt.address_lcase,
                status: queue::Status::Scheduled,
                flags: if rcpt.flags
                    & (RCPT_NOTIFY_DELAY
                        | RCPT_NOTIFY_FAILURE
                        | RCPT_NOTIFY_SUCCESS
                        | RCPT_NOTIFY_NEVER)
                    != 0
                {
                    rcpt.flags
                } else {
                    rcpt.flags | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_FAILURE
                },
                domain_idx: message.domains.len() - 1,
                orcpt: rcpt.dsn_info,
            });
        }
        message
    }

    pub async fn can_send_data(&mut self) -> Result<bool, ()> {
        if !self.data.rcpt_to.is_empty() {
            if self.data.messages_sent
                < *self.core.session.config.data.max_messages.eval(self).await
            {
                Ok(true)
            } else {
                tracing::debug!(
                    parent: &self.span,
                    context = "data",
                    event = "too-many-messages",
                    "Maximum number of messages per session exceeded."
                );
                self.write(b"451 4.4.5 Maximum number of messages per session exceeded.\r\n")
                    .await?;
                Ok(false)
            }
        } else {
            self.write(b"503 5.5.1 RCPT is required first.\r\n").await?;
            Ok(false)
        }
    }

    fn write_received(&self, headers: &mut Vec<u8>, id: u64) {
        headers.extend_from_slice(b"Received: from ");
        headers.extend_from_slice(self.data.helo_domain.as_bytes());
        headers.extend_from_slice(b" (");
        headers.extend_from_slice(
            self.data
                .iprev
                .as_ref()
                .and_then(|ir| ir.ptr.as_ref())
                .and_then(|ptr| ptr.first().map(|s| s.as_str()))
                .unwrap_or("unknown")
                .as_bytes(),
        );
        headers.extend_from_slice(b" [");
        headers.extend_from_slice(self.data.remote_ip.to_string().as_bytes());
        headers.extend_from_slice(b"])\r\n\t");
        self.stream.write_tls_header(headers);
        headers.extend_from_slice(b"by ");
        headers.extend_from_slice(self.instance.hostname.as_bytes());
        headers.extend_from_slice(b" (Stalwart SMTP) with ");
        headers.extend_from_slice(
            if self.stream.is_tls() {
                "ESMTPS"
            } else {
                "ESMTP"
            }
            .as_bytes(),
        );
        headers.extend_from_slice(b" id ");
        headers.extend_from_slice(format!("{id:X}").as_bytes());
        headers.extend_from_slice(b";\r\n\t");
        headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
        headers.extend_from_slice(b"\r\n");
    }
}
