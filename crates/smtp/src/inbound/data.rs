/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{TimeZone, Utc};
use common::{
    config::smtp::{auth::VerifyStrategy, session::Stage},
    listener::SessionStream,
    scripts::ScriptModification,
    webhooks::{WebhookMessageFailure, WebhookPayload, WebhookType},
};
use mail_auth::{
    common::{headers::HeaderWriter, verify::VerifySignature},
    dmarc, AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, ReceivedSpf,
};
use mail_builder::headers::{date::Date, message_id::generate_message_id_header};
use sieve::runtime::Variable;
use smtp_proto::{
    MAIL_BY_RETURN, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use store::write::now;
use tokio::{io::AsyncWriteExt, process::Command};
use utils::config::Rate;

use crate::{
    core::{Session, SessionAddress, State},
    inbound::milter::Modification,
    queue::{self, Message, QueueEnvelope, Schedule},
    scripts::ScriptResult,
};

use super::{ArcSeal, AuthResult, DkimSign};

impl<T: SessionStream> Session<T> {
    pub async fn queue_message(&mut self) -> Cow<'static, [u8]> {
        // Authenticate message
        let raw_message = Arc::new(std::mem::take(&mut self.data.message));
        let auth_message = if let Some(auth_message) = AuthenticatedMessage::parse_with_opts(
            &raw_message,
            self.core.core.smtp.mail_auth.dkim.strict,
        ) {
            auth_message
        } else {
            tracing::info!(
                    context = "data",
                    event = "parse-failed",
                    size = raw_message.len());

            self.send_failure_webhook(WebhookMessageFailure::ParseFailed)
                .await;

            return (&b"550 5.7.7 Failed to parse message.\r\n"[..]).into();
        };

        // Loop detection
        let dc = &self.core.core.smtp.session.data;
        let ac = &self.core.core.smtp.mail_auth;
        let rc = &self.core.core.smtp.report;
        if auth_message.received_headers_count()
            > self
                .core
                .core
                .eval_if(&dc.max_received_headers, self, self.data.session_id)
                .await
                .unwrap_or(50)
        {
            tracing::info!(
                context = "data",
                event = "loop-detected",
                return_path = self.data.mail_from.as_ref().unwrap().address,
                from = auth_message.from(),
                received_headers = auth_message.received_headers_count());

            self.send_failure_webhook(WebhookMessageFailure::LoopDetected)
                .await;

            return (&b"450 4.4.6 Too many Received headers. Possible loop detected.\r\n"[..])
                .into();
        }

        // Verify DKIM
        let dkim = self
            .core
            .core
            .eval_if(&ac.dkim.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let dmarc = self
            .core
            .core
            .eval_if(&ac.dmarc.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let dkim_output = if dkim.verify() || dmarc.verify() {
            let dkim_output = self
                .core
                .core
                .smtp
                .resolvers
                .dns
                .verify_dkim(&auth_message)
                .await;
            let rejected = dkim.is_strict()
                && !dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::Pass));

            // Send reports for failed signatures
            if let Some(rate) = self
                .core
                .core
                .eval_if::<Rate, _>(&rc.dkim.send, self, self.data.session_id)
                .await
            {
                for output in &dkim_output {
                    if let Some(rcpt) = output.failure_report_addr() {
                        self.send_dkim_report(rcpt, &auth_message, &rate, rejected, output)
                            .await;
                    }
                }
            }

            if rejected {
                tracing::info!(
                    context = "dkim",
                    event = "failed",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = ?dkim_output.iter().map(|d| d.result().to_string()).collect::<Vec<_>>(),
                    "No passing DKIM signatures found.");

                self.send_failure_webhook(WebhookMessageFailure::DkimPolicy)
                    .await;

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
                tracing::debug!(
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
        let arc = self
            .core
            .core
            .eval_if(&ac.arc.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let arc_sealer = self
            .core
            .core
            .eval_if::<String, _>(&ac.arc.seal, self, self.data.session_id)
            .await
            .and_then(|name| self.core.core.get_arc_sealer(&name));
        let arc_output = if arc.verify() || arc_sealer.is_some() {
            let arc_output = self
                .core
                .core
                .smtp
                .resolvers
                .dns
                .verify_arc(&auth_message)
                .await;

            if arc.is_strict()
                && !matches!(arc_output.result(), DkimResult::Pass | DkimResult::None)
            {
                tracing::info!(
                    context = "arc",
                    event = "auth-failed",
                    return_path = self.data.mail_from.as_ref().unwrap().address,
                    from = auth_message.from(),
                    result = %arc_output.result(),
                    "ARC validation failed.");

                self.send_failure_webhook(WebhookMessageFailure::ArcPolicy)
                    .await;

                return if matches!(arc_output.result(), DkimResult::TempError(_)) {
                    (&b"451 4.7.29 ARC validation failed.\r\n"[..]).into()
                } else {
                    (&b"550 5.7.29 ARC validation failed.\r\n"[..]).into()
                };
            } else {
                tracing::debug!(
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
        let mut auth_results = AuthenticationResults::new(&self.hostname);
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
        let is_report = self.is_report();
        let (dmarc_result, dmarc_policy) = match &self.data.spf_mail_from {
            Some(spf_output) if dmarc.verify() => {
                let dmarc_output = self
                    .core
                    .core
                    .smtp
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
                let dmarc_result = if dmarc_output.spf_result() == &DmarcResult::Pass
                    || dmarc_output.dkim_result() == &DmarcResult::Pass
                {
                    DmarcResult::Pass
                } else if dmarc_output.spf_result() != &DmarcResult::None {
                    dmarc_output.spf_result().clone()
                } else if dmarc_output.dkim_result() != &DmarcResult::None {
                    dmarc_output.dkim_result().clone()
                } else {
                    DmarcResult::None
                };
                let dmarc_policy = dmarc_output.policy();

                if !rejected {
                    tracing::debug!(
                    context = "dmarc",
                    event = "verify",
                    return_path = mail_from.address,
                    from = auth_message.from(),
                    dkim_result = %dmarc_output.dkim_result(),
                    spf_result = %dmarc_output.spf_result());
                } else {
                    tracing::info!(
                    context = "dmarc",
                    event = "auth-failed",
                    return_path = mail_from.address,
                    from = auth_message.from(),
                    dkim_result = %dmarc_output.dkim_result(),
                    spf_result = %dmarc_output.spf_result());
                }

                // Send DMARC report
                if dmarc_output.requested_reports() && !is_report {
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
                    self.send_failure_webhook(WebhookMessageFailure::DmarcPolicy)
                        .await;

                    return if is_temp_fail {
                        (&b"451 4.7.1 Email temporarily rejected per DMARC policy.\r\n"[..]).into()
                    } else {
                        (&b"550 5.7.1 Email rejected per DMARC policy.\r\n"[..]).into()
                    };
                }

                (dmarc_result.into(), dmarc_policy.into())
            }
            _ => (None, None),
        };

        // Analyze reports
        if is_report {
            self.core.analyze_report(raw_message.clone());
            if !rc.analysis.forward {
                self.data.messages_sent += 1;
                return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
            }
        }

        // Add Received header
        let message_id = self.core.inner.snowflake_id.generate().unwrap_or_else(now);
        let mut headers = Vec::with_capacity(64);
        if self
            .core
            .core
            .eval_if(&dc.add_received, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            self.write_received(&mut headers, message_id)
        }

        // Add authentication results header
        if self
            .core
            .core
            .eval_if(&dc.add_auth_results, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            auth_results.write_header(&mut headers);
        }

        // Add Received-SPF header
        if let Some(spf_output) = &self.data.spf_mail_from {
            if self
                .core
                .core
                .eval_if(&dc.add_received_spf, self, self.data.session_id)
                .await
                .unwrap_or(true)
            {
                ReceivedSpf::new(
                    spf_output,
                    self.data.remote_ip,
                    &self.data.helo_domain,
                    &mail_from.address_lcase,
                    &self.hostname,
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
                        tracing::info!(
                            context = "arc",
                            event = "seal-failed",
                            return_path = mail_from.address_lcase,
                            from = auth_message.from(),
                            "Failed to seal message: {}", err);
                    }
                }
            }
        }

        // Run Milter filters
        let mut modifications = Vec::new();
        match self.run_milters(Stage::Data, (&auth_message).into()).await {
            Ok(modifications_) => {
                if !modifications_.is_empty() {
                    tracing::debug!(
                    
                    context = "milter",
                    event = "accept",
                    modifications = modifications.iter().fold(String::new(), |mut s, m| {
                        use std::fmt::Write;
                        if !s.is_empty() {
                            s.push_str(", ");
                        }
                        let _ = write!(s, "{m}");
                        s
                    }),
                    "Milter filter(s) accepted message.");
                    modifications = modifications_;
                }
            }
            Err(response) => {
                self.send_failure_webhook(WebhookMessageFailure::MilterReject)
                    .await;

                return response.into_bytes();
            }
        };

        // Run MTA Hooks
        match self
            .run_mta_hooks(Stage::Data, (&auth_message).into())
            .await
        {
            Ok(modifications_) => {
                if !modifications_.is_empty() {
                    tracing::debug!(
                            
                            context = "mta_hook",
                            event = "accept",
                            "MTAHook filter(s) accepted message.");

                    modifications.retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                    modifications.extend(modifications_);
                }
            }
            Err(response) => {
                self.send_failure_webhook(WebhookMessageFailure::MilterReject)
                    .await;

                return response.into_bytes();
            }
        };

        // Apply modifications
        let mut edited_message = if !modifications.is_empty() {
            self.data
                .apply_milter_modifications(modifications, &auth_message)
        } else {
            None
        };

        // Pipe message
        for pipe in &dc.pipe_commands {
            if let Some(command_) = self
                .core
                .core
                .eval_if::<String, _>(&pipe.command, self, self.data.session_id)
                .await
            {
                let piped_message = edited_message.as_ref().unwrap_or(&raw_message).clone();
                let timeout = self
                    .core
                    .core
                    .eval_if(&pipe.timeout, self, self.data.session_id)
                    .await
                    .unwrap_or_else(|| Duration::from_secs(30));

                let mut command = Command::new(&command_);
                for argument in self
                    .core
                    .core
                    .eval_if::<Vec<String>, _>(&pipe.arguments, self, self.data.session_id)
                    .await
                    .unwrap_or_default()
                {
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
                                                edited_message = output.stdout.into();
                                            }

                                            tracing::debug!(
                                                context = "pipe",
                                                event = "success",
                                                command = command_,
                                                status = output.status.to_string());
                                        }
                                        Ok(Err(err)) => {
                                            tracing::warn!(
                                                context = "pipe",
                                                event = "exec-error",
                                                command = command_,
                                                reason = %err);
                                        }
                                        Err(_) => {
                                            tracing::warn!(
                                                context = "pipe",
                                                event = "timeout",
                                                command = command_);
                                        }
                                    }
                                }
                                Ok(Err(err)) => {
                                    tracing::warn!(
                                        context = "pipe",
                                        event = "write-error",
                                        command = command_,
                                        reason = %err);
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        context = "pipe",
                                        event = "stdin-timeout",
                                        command = command_);
                                }
                            }
                        } else {
                            tracing::warn!(
                                context = "pipe",
                                event = "stdin-failed",
                                command = command_);
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                                context = "pipe",
                                event = "spawn-error",
                                command = command_,
                                reason = %err);
                    }
                }
            }
        }

        // Sieve filtering
        if let Some(script) = self
            .core
            .core
            .eval_if::<String, _>(&dc.script, self, self.data.session_id)
            .await
            .and_then(|name| self.core.core.get_sieve_script(&name))
        {
            let params = self
                .build_script_parameters("data")
                .with_message(edited_message.as_ref().unwrap_or(&raw_message))
                .with_auth_headers(&headers)
                .set_variable(
                    "arc.result",
                    arc_output
                        .as_ref()
                        .map(|a| a.result().as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dkim.result",
                    dkim_output
                        .iter()
                        .find(|r| matches!(r.result(), DkimResult::Pass))
                        .or_else(|| dkim_output.first())
                        .map(|r| r.result().as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dkim.domains",
                    dkim_output
                        .iter()
                        .filter_map(|r| {
                            if matches!(r.result(), DkimResult::Pass) {
                                r.signature()
                                    .map(|s| Variable::from(s.domain().to_lowercase()))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                )
                .set_variable(
                    "dmarc.result",
                    dmarc_result
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dmarc.policy",
                    dmarc_policy
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or_default(),
                );

            let modifications = match self.run_script(script.clone(), params).await {
                ScriptResult::Accept { modifications } => modifications,
                ScriptResult::Replace {
                    message,
                    modifications,
                } => {
                    edited_message = message.into();
                    modifications
                }
                ScriptResult::Reject(message) => {
                    tracing::info!(
                        context = "sieve",
                        event = "reject",
                        reason = message);

                    self.send_failure_webhook(WebhookMessageFailure::SieveReject)
                        .await;

                    return message.into_bytes().into();
                }
                ScriptResult::Discard => {
                    self.send_failure_webhook(WebhookMessageFailure::SieveDiscard)
                        .await;

                    return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
                }
            };

            // Apply modifications
            for modification in modifications {
                match modification {
                    ScriptModification::AddHeader { name, value } => {
                        headers.extend_from_slice(name.as_bytes());
                        headers.extend_from_slice(b": ");
                        headers.extend_from_slice(value.as_bytes());
                        if !value.ends_with('\n') {
                            headers.extend_from_slice(b"\r\n");
                        }
                    }
                    ScriptModification::SetEnvelope { name, value } => {
                        self.data.apply_envelope_modification(name, value);
                    }
                }
            }
        }

        // Build message
        let mail_from = self.data.mail_from.clone().unwrap();
        let rcpt_to = std::mem::take(&mut self.data.rcpt_to);
        let mut message = self.build_message(mail_from, rcpt_to, message_id).await;

        // Add Return-Path
        if self
            .core
            .core
            .eval_if(&dc.add_return_path, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            headers.extend_from_slice(b"Return-Path: <");
            headers.extend_from_slice(message.return_path.as_bytes());
            headers.extend_from_slice(b">\r\n");
        }

        // Add any missing headers
        if !auth_message.has_date_header()
            && self
                .core
                .core
                .eval_if(&dc.add_date, self, self.data.session_id)
                .await
                .unwrap_or(true)
        {
            headers.extend_from_slice(b"Date: ");
            headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        if !auth_message.has_message_id_header()
            && self
                .core
                .core
                .eval_if(&dc.add_message_id, self, self.data.session_id)
                .await
                .unwrap_or(true)
        {
            headers.extend_from_slice(b"Message-ID: ");
            let _ = generate_message_id_header(&mut headers, &self.hostname);
            headers.extend_from_slice(b"\r\n");
        }

        // DKIM sign
        let raw_message = edited_message
            .as_deref()
            .unwrap_or_else(|| raw_message.as_slice());
        for signer in self
            .core
            .core
            .eval_if::<Vec<String>, _>(&ac.dkim.sign, self, self.data.session_id)
            .await
            .unwrap_or_default()
        {
            if let Some(signer) = self.core.core.get_dkim_signer(&signer) {
                match signer.sign_chained(&[headers.as_ref(), raw_message]) {
                    Ok(signature) => {
                        signature.write_header(&mut headers);
                    }
                    Err(err) => {
                        tracing::info!(
                        context = "dkim",
                        event = "sign-failed",
                        return_path = message.return_path,
                        "Failed to sign message: {}", err);
                    }
                }
            }
        }

        // Update size
        message.size = raw_message.len() + headers.len();

        // Verify queue quota
        if self.core.has_quota(&mut message).await {
            // Prepare webhook event
            let queue_id = message.id;
            let webhook_event = self
                .core
                .core
                .has_webhook_subscribers(WebhookType::MessageAccepted)
                .then(|| WebhookPayload::MessageAccepted {
                    id: queue_id,
                    remote_ip: self.data.remote_ip.into(),
                    local_port: self.data.local_port.into(),
                    authenticated_as: (!self.data.authenticated_as.is_empty())
                        .then(|| self.data.authenticated_as.clone()),
                    return_path: message.return_path_lcase.clone(),
                    recipients: message
                        .recipients
                        .iter()
                        .map(|r| r.address_lcase.clone())
                        .collect(),
                    next_retry: Utc
                        .timestamp_opt(message.next_delivery_event() as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                    next_dsn: Utc
                        .timestamp_opt(message.next_dsn() as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                    expires: Utc
                        .timestamp_opt(message.expires() as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                    size: message.size,
                });

            // Queue message
            if message.queue(Some(&headers), raw_message, &self.core).await {
                // Send webhook event
                if let Some(event) = webhook_event {
                    self.core
                        .inner
                        .ipc
                        .send_webhook(WebhookType::MessageAccepted, event)
                        .await;
                }

                self.state = State::Accepted(queue_id);
                self.data.messages_sent += 1;
                (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into()
            } else {
                self.send_failure_webhook(WebhookMessageFailure::ServerFailure)
                    .await;

                (b"451 4.3.5 Unable to accept message at this time.\r\n"[..]).into()
            }
        } else {
            tracing::warn!(
                
                context = "queue",
                event = "quota-exceeded",
                from = message.return_path,
                "Queue quota exceeded, rejecting message."
            );

            self.send_failure_webhook(WebhookMessageFailure::QuotaExceeded)
                .await;

            (b"452 4.3.1 Mail system full, try again later.\r\n"[..]).into()
        }
    }

    pub async fn build_message(
        &self,
        mail_from: SessionAddress,
        mut rcpt_to: Vec<SessionAddress>,
        id: u64,
    ) -> Message {
        // Build message
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut message = Message {
            id,
            created,
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(rcpt_to.len()),
            domains: Vec::with_capacity(3),
            flags: mail_from.flags,
            priority: self.data.priority,
            size: 0,
            env_id: mail_from.dsn_info,
            blob_hash: Default::default(),
            quota_keys: Vec::new(),
        };

        // Add recipients
        let future_release = Duration::from_secs(self.data.future_release);
        rcpt_to.sort_unstable();
        for rcpt in rcpt_to {
            if message
                .domains
                .last()
                .map_or(true, |d| d.domain != rcpt.domain)
            {
                let rcpt_idx = message.domains.len();
                message.domains.push(queue::Domain {
                    retry: Schedule::now(),
                    notify: Schedule::now(),
                    expires: 0,
                    status: queue::Status::Scheduled,
                    domain: rcpt.domain,
                });

                let envelope = QueueEnvelope::new(&message, rcpt_idx);

                // Set next retry time
                let retry = if self.data.future_release == 0 {
                    queue::Schedule::now()
                } else {
                    queue::Schedule::later(future_release)
                };

                // Set expiration and notification times
                let config = &self.core.core.smtp.queue;
                let (num_intervals, next_notify) = self
                    .core
                    .core
                    .eval_if::<Vec<Duration>, _>(&config.notify, &envelope, self.data.session_id)
                    .await
                    .and_then(|v| (v.len(), v.into_iter().next()?).into())
                    .unwrap_or_else(|| (1, Duration::from_secs(86400)));
                let (notify, expires) = if self.data.delivery_by == 0 {
                    (
                        queue::Schedule::later(future_release + next_notify),
                        now()
                            + future_release.as_secs()
                            + self
                                .core
                                .core
                                .eval_if(&config.expire, &envelope, self.data.session_id)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 86400))
                                .as_secs(),
                    )
                } else if (message.flags & MAIL_BY_RETURN) != 0 {
                    (
                        queue::Schedule::later(future_release + next_notify),
                        now() + self.data.delivery_by as u64,
                    )
                } else {
                    let expire = self
                        .core
                        .core
                        .eval_if(&config.expire, &envelope, self.data.session_id)
                        .await
                        .unwrap_or_else(|| Duration::from_secs(5 * 86400));
                    let expire_secs = expire.as_secs();
                    let notify = if self.data.delivery_by.is_positive() {
                        let notify_at = self.data.delivery_by as u64;
                        if expire_secs > notify_at {
                            Duration::from_secs(notify_at)
                        } else {
                            next_notify
                        }
                    } else {
                        let notify_at = -self.data.delivery_by as u64;
                        if expire_secs > notify_at {
                            Duration::from_secs(expire_secs - notify_at)
                        } else {
                            next_notify
                        }
                    };
                    let mut notify = queue::Schedule::later(future_release + notify);
                    notify.inner = (num_intervals - 1) as u32; // Disable further notification attempts

                    (notify, now() + expire_secs)
                };

                // Update domain
                let domain = message.domains.last_mut().unwrap();
                domain.retry = retry;
                domain.notify = notify;
                domain.expires = expires;
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
                < self
                    .core
                    .core
                    .eval_if(
                        &self.core.core.smtp.session.data.max_messages,
                        self,
                        self.data.session_id,
                    )
                    .await
                    .unwrap_or(10)
            {
                Ok(true)
            } else {
                tracing::debug!(
                    
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
                .and_then(|ptr| ptr.first().map(|s| s.strip_suffix('.').unwrap_or(s)))
                .unwrap_or("unknown")
                .as_bytes(),
        );
        headers.extend_from_slice(b" [");
        headers.extend_from_slice(self.data.remote_ip.to_string().as_bytes());
        headers.extend_from_slice(b"])\r\n\t");
        if self.stream.is_tls() {
            let (version, cipher) = self.stream.tls_version_and_cipher();
            headers.extend_from_slice(b"(using ");
            headers.extend_from_slice(version.as_bytes());
            headers.extend_from_slice(b" with cipher ");
            headers.extend_from_slice(cipher.as_bytes());
            headers.extend_from_slice(b")\r\n\t");
        }
        headers.extend_from_slice(b"by ");
        headers.extend_from_slice(self.hostname.as_bytes());
        headers.extend_from_slice(b" (Stalwart SMTP) with ");
        headers.extend_from_slice(
            match (self.stream.is_tls(), self.data.authenticated_as.is_empty()) {
                (true, true) => b"ESMTPS",
                (true, false) => b"ESMTPSA",
                (false, true) => b"ESMTP",
                (false, false) => b"ESMTPA",
            },
        );
        headers.extend_from_slice(b" id ");
        headers.extend_from_slice(format!("{id:X}").as_bytes());
        headers.extend_from_slice(b";\r\n\t");
        headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
        headers.extend_from_slice(b"\r\n");
    }

    async fn send_failure_webhook(&self, reason: WebhookMessageFailure) {
        if self
            .core
            .core
            .has_webhook_subscribers(WebhookType::MessageRejected)
        {
            self.core
                .inner
                .ipc
                .send_webhook(
                    WebhookType::MessageRejected,
                    WebhookPayload::MessageRejected {
                        reason,
                        remote_ip: self.data.remote_ip,
                        local_port: self.data.local_port,
                        authenticated_as: (!self.data.authenticated_as.is_empty())
                            .then(|| self.data.authenticated_as.clone()),
                        return_path: self
                            .data
                            .mail_from
                            .as_ref()
                            .map(|m| m.address_lcase.clone()),
                        recipients: self
                            .data
                            .rcpt_to
                            .iter()
                            .map(|r| r.address_lcase.clone())
                            .collect(),
                    },
                )
                .await;
        }
    }
}
