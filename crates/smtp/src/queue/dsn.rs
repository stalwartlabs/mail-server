/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use chrono::{TimeZone, Utc};
use common::webhooks::{WebhookDSN, WebhookDSNType, WebhookPayload, WebhookType};
use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::HeaderType;
use mail_builder::mime::{make_boundary, BodyPart, MimePart};
use mail_builder::MessageBuilder;
use mail_parser::DateTime;
use smtp_proto::{
    Response, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use std::fmt::Write;
use std::time::Duration;
use store::write::now;

use crate::core::SMTP;

use super::{
    Domain, Error, ErrorDetails, HostResponse, Message, QueueEnvelope, Recipient, Status,
    RCPT_DSN_SENT, RCPT_STATUS_CHANGED,
};

impl SMTP {
    pub async fn send_dsn(&self, message: &mut Message) {
        // Send webhook event
        self.send_dsn_webhook(message).await;

        if !message.return_path.is_empty() {
            // Build DSN
            if let Some(dsn) = message.build_dsn(self).await {
                let mut dsn_message = self.new_message("", "", "");
                dsn_message
                    .add_recipient_parts(
                        &message.return_path,
                        &message.return_path_lcase,
                        &message.return_path_domain,
                        self,
                    )
                    .await;

                // Sign message
                let signature = self
                    .sign_message(message, &self.core.smtp.queue.dsn.sign, &dsn)
                    .await;

                // Queue DSN
                dsn_message.queue(signature.as_deref(), &dsn, self).await;
            }
        } else {
            // Handle double bounce
            message.handle_double_bounce();
        }
    }

    async fn send_dsn_webhook(&self, message: &Message) {
        let typ = if !message.return_path.is_empty() {
            WebhookType::DSN
        } else {
            WebhookType::DoubleBounce
        };
        if !self.core.has_webhook_subscribers(typ) {
            return;
        }

        let now = now();
        let mut webhook_data = Vec::new();

        for rcpt in &message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT) {
                continue;
            }

            let domain = &message.domains[rcpt.domain_idx];
            match &rcpt.status {
                Status::Completed(response) => {
                    webhook_data.push(WebhookDSN {
                        address: rcpt.address_lcase.clone(),
                        typ: WebhookDSNType::Success,
                        remote_host: response.hostname.clone().into(),
                        message: response.response.to_string(),
                        next_retry: None,
                        expires: None,
                        retry_count: None,
                    });
                }
                Status::TemporaryFailure(response) if domain.notify.due <= now => {
                    webhook_data.push(WebhookDSN {
                        address: rcpt.address_lcase.clone(),
                        typ: WebhookDSNType::TemporaryFailure,
                        remote_host: response.hostname.entity.clone().into(),
                        message: response.response.to_string(),
                        next_retry: Utc.timestamp_opt(domain.retry.due as i64, 0).single(),
                        expires: Utc.timestamp_opt(domain.expires as i64, 0).single(),
                        retry_count: domain.retry.inner.into(),
                    });
                }
                Status::PermanentFailure(response) => {
                    webhook_data.push(WebhookDSN {
                        address: rcpt.address_lcase.clone(),
                        typ: WebhookDSNType::PermanentFailure,
                        remote_host: response.hostname.entity.clone().into(),
                        message: response.response.to_string(),
                        next_retry: None,
                        expires: None,
                        retry_count: domain.retry.inner.into(),
                    });
                }
                Status::Scheduled => {
                    // There is no status for this address, use the domain's status.
                    match &domain.status {
                        Status::PermanentFailure(err) => {
                            webhook_data.push(WebhookDSN {
                                address: rcpt.address_lcase.clone(),
                                typ: WebhookDSNType::PermanentFailure,
                                remote_host: None,
                                message: err.to_string(),
                                next_retry: None,
                                expires: None,
                                retry_count: domain.retry.inner.into(),
                            });
                        }
                        Status::TemporaryFailure(err) if domain.notify.due <= now => {
                            webhook_data.push(WebhookDSN {
                                address: rcpt.address_lcase.clone(),
                                typ: WebhookDSNType::TemporaryFailure,
                                remote_host: None,
                                message: err.to_string(),
                                next_retry: Utc.timestamp_opt(domain.retry.due as i64, 0).single(),
                                expires: Utc.timestamp_opt(domain.expires as i64, 0).single(),
                                retry_count: domain.retry.inner.into(),
                            });
                        }
                        Status::Scheduled if domain.notify.due <= now => {
                            webhook_data.push(WebhookDSN {
                                address: rcpt.address_lcase.clone(),
                                typ: WebhookDSNType::TemporaryFailure,
                                remote_host: None,
                                message: "Concurrency limited".to_string(),
                                next_retry: Utc.timestamp_opt(domain.retry.due as i64, 0).single(),
                                expires: Utc.timestamp_opt(domain.expires as i64, 0).single(),
                                retry_count: domain.retry.inner.into(),
                            });
                        }
                        _ => continue,
                    }
                }
                _ => continue,
            }
        }

        // Send webhook event
        if !webhook_data.is_empty() {
            self.inner
                .ipc
                .send_webhook(
                    typ,
                    WebhookPayload::DSN {
                        id: message.id,
                        sender: message.return_path_lcase.clone(),
                        status: webhook_data,
                        created: Utc
                            .timestamp_opt(message.created as i64, 0)
                            .single()
                            .unwrap_or_else(Utc::now),
                    },
                )
                .await;
        }
    }
}

impl Message {
    pub async fn build_dsn(&mut self, core: &SMTP) -> Option<Vec<u8>> {
        let config = &core.core.smtp.queue;
        let now = now();

        let mut txt_success = String::new();
        let mut txt_delay = String::new();
        let mut txt_failed = String::new();
        let mut dsn = String::new();

        for rcpt in &mut self.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                continue;
            }
            let domain = &self.domains[rcpt.domain_idx];
            match &rcpt.status {
                Status::Completed(response) => {
                    rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                    if !rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_success);
                }
                Status::TemporaryFailure(response)
                    if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                {
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    domain.write_dsn_will_retry_until(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_delay);
                }
                Status::PermanentFailure(response) => {
                    rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                    if !rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_failed);
                }
                Status::Scheduled => {
                    // There is no status for this address, use the domain's status.
                    match &domain.status {
                        Status::PermanentFailure(err) => {
                            rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                            if !rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                                continue;
                            }
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_failed);
                        }
                        Status::TemporaryFailure(err)
                            if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                        {
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            domain.write_dsn_will_retry_until(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_delay);
                        }
                        Status::Scheduled
                            if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                        {
                            // This case should not happen under normal circumstances
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            domain.write_dsn_will_retry_until(&mut dsn);
                            Error::ConcurrencyLimited.write_dsn_text(
                                &rcpt.address,
                                &domain.domain,
                                &mut txt_delay,
                            );
                        }
                        Status::Completed(_) => {
                            #[cfg(feature = "test_mode")]
                            panic!("This should not have happened.");
                        }
                        _ => continue,
                    }
                }
                _ => continue,
            }

            dsn.push_str("\r\n");
        }

        // Build text response
        let txt_len = txt_success.len() + txt_delay.len() + txt_failed.len();
        if txt_len == 0 {
            return None;
        }

        let has_success = !txt_success.is_empty();
        let has_delay = !txt_delay.is_empty();
        let has_failure = !txt_failed.is_empty();

        let mut txt = String::with_capacity(txt_len + 128);
        let (subject, is_mixed) = if has_success && !has_delay && !has_failure {
            txt.push_str(
                "Your message has been successfully delivered to the following recipients:\r\n\r\n",
            );
            ("Successfully delivered message", false)
        } else if has_delay && !has_success && !has_failure {
            txt.push_str("There was a temporary problem delivering your message to the following recipients:\r\n\r\n");
            ("Warning: Delay in message delivery", false)
        } else if has_failure && !has_success && !has_delay {
            txt.push_str(
                "Your message could not be delivered to the following recipients:\r\n\r\n",
            );
            ("Failed to deliver message", false)
        } else if has_success {
            txt.push_str("Your message has been partially delivered:\r\n\r\n");
            ("Partially delivered message", true)
        } else {
            txt.push_str("Your message could not be delivered to some recipients:\r\n\r\n");
            (
                "Warning: Temporary and permanent failures during message delivery",
                true,
            )
        };

        if has_success {
            if is_mixed {
                txt.push_str(
                    "    ----- Delivery to the following addresses was successful -----\r\n",
                );
            }

            txt.push_str(&txt_success);
            txt.push_str("\r\n");
        }

        if has_delay {
            if is_mixed {
                txt.push_str(
                    "    ----- There was a temporary problem delivering to these addresses -----\r\n",
                );
            }
            txt.push_str(&txt_delay);
            txt.push_str("\r\n");
        }

        if has_failure {
            if is_mixed {
                txt.push_str("    ----- Delivery to the following addresses failed -----\r\n");
            }
            txt.push_str(&txt_failed);
            txt.push_str("\r\n");
        }

        // Update next delay notification time
        if has_delay {
            let mut changes = Vec::new();
            for (domain_idx, domain) in self.domains.iter().enumerate() {
                if matches!(
                    &domain.status,
                    Status::TemporaryFailure(_) | Status::Scheduled
                ) && domain.notify.due <= now
                {
                    let envelope = QueueEnvelope::new(self, domain_idx);

                    if let Some(next_notify) = core
                        .core
                        .eval_if::<Vec<Duration>, _>(&config.notify, &envelope, self.id)
                        .await
                        .and_then(|notify| {
                            notify.into_iter().nth((domain.notify.inner + 1) as usize)
                        })
                    {
                        changes.push((domain_idx, 1, now + next_notify.as_secs()));
                    } else {
                        changes.push((domain_idx, 0, domain.expires + 10));
                    }
                }
            }

            for (domain_idx, inner, due) in changes {
                let domain = &mut self.domains[domain_idx];
                domain.notify.inner += inner;
                domain.notify.due = due;
            }
        }

        // Obtain hostname and sender addresses
        let from_name = core
            .core
            .eval_if(&config.dsn.name, self, self.id)
            .await
            .unwrap_or_else(|| String::from("Mail Delivery Subsystem"));
        let from_addr = core
            .core
            .eval_if(&config.dsn.address, self, self.id)
            .await
            .unwrap_or_else(|| String::from("MAILER-DAEMON@localhost"));
        let reporting_mta = core
            .core
            .eval_if(&core.core.smtp.report.submitter, self, self.id)
            .await
            .unwrap_or_else(|| String::from("localhost"));

        // Prepare DSN
        let mut dsn_header = String::with_capacity(dsn.len() + 128);
        self.write_dsn_headers(&mut dsn_header, &reporting_mta);
        let dsn = dsn_header + dsn.as_str();

        // Fetch up to 1024 bytes of message headers
        let headers = match core
            .core
            .storage
            .blob
            .get_blob(self.blob_hash.as_slice(), 0..1024)
            .await
        {
            Ok(Some(mut buf)) => {
                let mut prev_ch = 0;
                let mut last_lf = buf.len();
                for (pos, &ch) in buf.iter().enumerate() {
                    match ch {
                        b'\n' => {
                            last_lf = pos + 1;
                            if prev_ch != b'\n' {
                                prev_ch = ch;
                            } else {
                                break;
                            }
                        }
                        b'\r' => (),
                        0 => break,
                        _ => {
                            prev_ch = ch;
                        }
                    }
                }
                if last_lf < 1024 {
                    buf.truncate(last_lf);
                }
                String::from_utf8(buf).unwrap_or_default()
            }
            Ok(None) => {
                tracing::error!(
                    context = "queue",
                    event = "error",
                    "Failed to open blob {:?}: not found",
                    self.blob_hash
                );
                String::new()
            }
            Err(err) => {
                tracing::error!(
                    context = "queue",
                    event = "error",
                    "Failed to open blob {:?}: {}",
                    self.blob_hash,
                    err
                );
                String::new()
            }
        };

        // Build message
        MessageBuilder::new()
            .from((from_name.as_str(), from_addr.as_str()))
            .header("To", HeaderType::Text(self.return_path.as_str().into()))
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("<{}@{}>", make_boundary("."), reporting_mta))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
                BodyPart::Multipart(vec![
                    MimePart::new(ContentType::new("text/plain"), BodyPart::Text(txt.into())),
                    MimePart::new(
                        ContentType::new("message/delivery-status"),
                        BodyPart::Text(dsn.into()),
                    ),
                    MimePart::new(
                        ContentType::new("message/rfc822"),
                        BodyPart::Text(headers.into()),
                    ),
                ]),
            ))
            .write_to_vec()
            .unwrap_or_default()
            .into()
    }

    fn handle_double_bounce(&mut self) {
        let mut is_double_bounce = Vec::with_capacity(0);

        for rcpt in &mut self.recipients {
            if !rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                match &rcpt.status {
                    Status::PermanentFailure(err) => {
                        rcpt.flags |= RCPT_DSN_SENT;
                        let mut dsn = String::new();
                        err.write_dsn_text(&rcpt.address, &mut dsn);
                        is_double_bounce.push(dsn);
                    }
                    Status::Scheduled => {
                        let domain = &self.domains[rcpt.domain_idx];
                        if let Status::PermanentFailure(err) = &domain.status {
                            rcpt.flags |= RCPT_DSN_SENT;
                            let mut dsn = String::new();
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut dsn);
                            is_double_bounce.push(dsn);
                        }
                    }
                    _ => (),
                }
            }
        }

        let now = now();
        for domain in &mut self.domains {
            if domain.notify.due <= now {
                domain.notify.due = domain.expires + 10;
            }
        }

        if !is_double_bounce.is_empty() {
            tracing::info!(

                context = "queue",
                event = "double-bounce",
                id = self.id,
                failures = ?is_double_bounce,
                "Failed delivery of message with null return path.",
            );
        }
    }
}

impl HostResponse<String> {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let _ = write!(
            dsn,
            "<{}> (delivered to '{}' with code {} ({}.{}.{}) '",
            addr,
            self.hostname,
            self.response.code,
            self.response.esc[0],
            self.response.esc[1],
            self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl HostResponse<ErrorDetails> {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let _ = write!(dsn, "<{}> (host '{}' rejected ", addr, self.hostname.entity);

        if !self.hostname.details.is_empty() {
            let _ = write!(dsn, "command '{}'", self.hostname.details,);
        } else {
            dsn.push_str("transaction");
        }

        let _ = write!(
            dsn,
            " with code {} ({}.{}.{}) '",
            self.response.code, self.response.esc[0], self.response.esc[1], self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl Error {
    fn write_dsn_text(&self, addr: &str, domain: &str, dsn: &mut String) {
        match self {
            Error::UnexpectedResponse(response) => {
                response.write_dsn_text(addr, dsn);
            }
            Error::DnsError(err) => {
                let _ = write!(dsn, "<{addr}> (failed to lookup '{domain}': {err})\r\n",);
            }
            Error::ConnectionError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (connection to '{}' failed: {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::TlsError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (TLS error from '{}': {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::DaneError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (DANE failed to authenticate '{}': {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::MtaStsError(details) => {
                let _ = write!(
                    dsn,
                    "<{addr}> (MTA-STS failed to authenticate '{domain}': {details})\r\n",
                );
            }
            Error::RateLimited => {
                let _ = write!(dsn, "<{addr}> (rate limited)\r\n");
            }
            Error::ConcurrencyLimited => {
                let _ = write!(
                    dsn,
                    "<{addr}> (too many concurrent connections to remote server)\r\n",
                );
            }
            Error::Io(err) => {
                let _ = write!(dsn, "<{addr}> (queue error: {err})\r\n");
            }
        }
    }
}

impl Message {
    fn write_dsn_headers(&self, dsn: &mut String, reporting_mta: &str) {
        let _ = write!(dsn, "Reporting-MTA: dns;{reporting_mta}\r\n");
        dsn.push_str("Arrival-Date: ");
        dsn.push_str(&DateTime::from_timestamp(self.created as i64).to_rfc822());
        dsn.push_str("\r\n");
        if let Some(env_id) = &self.env_id {
            let _ = write!(dsn, "Original-Envelope-Id: {env_id}\r\n");
        }
        dsn.push_str("\r\n");
    }
}

impl Recipient {
    fn write_dsn(&self, dsn: &mut String) {
        if let Some(orcpt) = &self.orcpt {
            let _ = write!(dsn, "Original-Recipient: rfc822;{orcpt}\r\n");
        }
        let _ = write!(dsn, "Final-Recipient: rfc822;{}\r\n", self.address);
    }
}

impl Domain {
    fn write_dsn_will_retry_until(&self, dsn: &mut String) {
        let now = now();
        if self.expires > now {
            dsn.push_str("Will-Retry-Until: ");
            dsn.push_str(&DateTime::from_timestamp(self.expires as i64).to_rfc822());
            dsn.push_str("\r\n");
        }
    }
}

impl<T, E> Status<T, E> {
    pub fn into_permanent(self) -> Self {
        match self {
            Status::TemporaryFailure(v) => Status::PermanentFailure(v),
            v => v,
        }
    }

    pub fn into_temporary(self) -> Self {
        match self {
            Status::PermanentFailure(err) => Status::TemporaryFailure(err),
            other => other,
        }
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Status::PermanentFailure(_))
    }

    fn write_dsn_action(&self, dsn: &mut String) {
        dsn.push_str("Action: ");
        dsn.push_str(match self {
            Status::Completed(_) => "delivered",
            Status::PermanentFailure(_) => "failed",
            Status::TemporaryFailure(_) | Status::Scheduled => "delayed",
        });
        dsn.push_str("\r\n");
    }
}

impl Status<HostResponse<String>, HostResponse<ErrorDetails>> {
    fn write_dsn(&self, dsn: &mut String) {
        self.write_dsn_action(dsn);
        self.write_dsn_status(dsn);
        self.write_dsn_diagnostic(dsn);
        self.write_dsn_remote_mta(dsn);
    }

    fn write_dsn_status(&self, dsn: &mut String) {
        dsn.push_str("Status: ");
        if let Status::Completed(HostResponse { response, .. })
        | Status::PermanentFailure(HostResponse { response, .. })
        | Status::TemporaryFailure(HostResponse { response, .. }) = self
        {
            response.write_dsn_status(dsn);
        }
        dsn.push_str("\r\n");
    }

    fn write_dsn_remote_mta(&self, dsn: &mut String) {
        dsn.push_str("Remote-MTA: dns;");
        if let Status::Completed(HostResponse { hostname, .. })
        | Status::PermanentFailure(HostResponse {
            hostname: ErrorDetails {
                entity: hostname, ..
            },
            ..
        })
        | Status::TemporaryFailure(HostResponse {
            hostname: ErrorDetails {
                entity: hostname, ..
            },
            ..
        }) = self
        {
            dsn.push_str(hostname);
        }
        dsn.push_str("\r\n");
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        if let Status::PermanentFailure(details) | Status::TemporaryFailure(details) = self {
            details.response.write_dsn_diagnostic(dsn);
        }
    }
}

impl Status<(), Error> {
    fn write_dsn(&self, dsn: &mut String) {
        self.write_dsn_action(dsn);
        self.write_dsn_status(dsn);
        self.write_dsn_diagnostic(dsn);
        self.write_dsn_remote_mta(dsn);
    }

    fn write_dsn_status(&self, dsn: &mut String) {
        if let Status::PermanentFailure(err) | Status::TemporaryFailure(err) = self {
            dsn.push_str("Status: ");
            if let Error::UnexpectedResponse(response) = err {
                response.response.write_dsn_status(dsn);
            } else {
                dsn.push_str(if matches!(self, Status::PermanentFailure(_)) {
                    "5.0.0"
                } else {
                    "4.0.0"
                });
            }
            dsn.push_str("\r\n");
        }
    }

    fn write_dsn_remote_mta(&self, dsn: &mut String) {
        if let Status::PermanentFailure(err) | Status::TemporaryFailure(err) = self {
            match err {
                Error::UnexpectedResponse(HostResponse {
                    hostname: details, ..
                })
                | Error::ConnectionError(details)
                | Error::TlsError(details)
                | Error::DaneError(details) => {
                    dsn.push_str("Remote-MTA: dns;");
                    dsn.push_str(&details.entity);
                    dsn.push_str("\r\n");
                }
                _ => (),
            }
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        if let Status::PermanentFailure(Error::UnexpectedResponse(response))
        | Status::TemporaryFailure(Error::UnexpectedResponse(response)) = self
        {
            response.response.write_dsn_diagnostic(dsn);
        }
    }
}

impl WriteDsn for Response<String> {
    fn write_dsn_status(&self, dsn: &mut String) {
        if self.esc[0] > 0 {
            let _ = write!(dsn, "{}.{}.{}", self.esc[0], self.esc[1], self.esc[2]);
        } else {
            let _ = write!(
                dsn,
                "{}.{}.{}",
                self.code / 100,
                (self.code / 10) % 10,
                self.code % 10
            );
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        let _ = write!(dsn, "Diagnostic-Code: smtp;{} ", self.code);
        self.write_response(dsn);
        dsn.push_str("\r\n");
    }

    fn write_response(&self, dsn: &mut String) {
        for ch in self.message.chars() {
            if ch != '\n' && ch != '\r' {
                dsn.push(ch);
            }
        }
    }
}

trait WriteDsn {
    fn write_dsn_status(&self, dsn: &mut String);
    fn write_dsn_diagnostic(&self, dsn: &mut String);
    fn write_response(&self, dsn: &mut String);
}
