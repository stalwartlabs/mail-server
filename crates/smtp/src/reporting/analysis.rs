/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    collections::hash_map::Entry,
    io::{Cursor, Read},
    sync::Arc,
    time::SystemTime,
};

use ahash::AHashMap;
use common::webhooks::{WebhookPayload, WebhookTlsPolicy, WebhookType};
use mail_auth::{
    flate2::read::GzDecoder,
    report::{tlsrpt::TlsReport, ActionDisposition, DmarcResult, Feedback, Report},
    zip,
};
use mail_parser::{DateTime, MessageParser, MimeHeaders, PartType};

use store::{
    write::{now, BatchBuilder, Bincode, ReportClass, ValueClass},
    Serialize,
};

use crate::core::SMTP;

enum Compression {
    None,
    Gzip,
    Zip,
}

enum Format<D, T, A> {
    Dmarc(D),
    Tls(T),
    Arf(A),
}

struct ReportData<'x> {
    compression: Compression,
    format: Format<(), (), ()>,
    data: &'x [u8],
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct IncomingReport<T> {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub report: T,
}

impl SMTP {
    pub fn analyze_report(&self, message: Arc<Vec<u8>>) {
        let core = self.clone();
        tokio::spawn(async move {
            let message = if let Some(message) = MessageParser::default().parse(message.as_ref()) {
                message
            } else {
                trc::event!(context = "report", "Failed to parse message.");
                return;
            };
            let from = message
                .from()
                .and_then(|a| a.last())
                .and_then(|a| a.address())
                .unwrap_or_default()
                .to_string();
            let to = message.to().map_or_else(Vec::new, |a| {
                a.iter()
                    .filter_map(|a| a.address())
                    .map(|a| a.to_string())
                    .collect()
            });
            let subject = message.subject().unwrap_or_default().to_string();
            let mut reports = Vec::new();

            for part in &message.parts {
                match &part.body {
                    PartType::Text(report) => {
                        if part
                            .content_type()
                            .and_then(|ct| ct.subtype())
                            .map_or(false, |t| t.eq_ignore_ascii_case("xml"))
                            || part
                                .attachment_name()
                                .and_then(|n| n.rsplit_once('.'))
                                .map_or(false, |(_, e)| e.eq_ignore_ascii_case("xml"))
                        {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Dmarc(()),
                                data: report.as_bytes(),
                            });
                        } else if part.is_content_type("message", "feedback-report") {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Arf(()),
                                data: report.as_bytes(),
                            });
                        }
                    }
                    PartType::Binary(report) | PartType::InlineBinary(report) => {
                        if part.is_content_type("message", "feedback-report") {
                            reports.push(ReportData {
                                compression: Compression::None,
                                format: Format::Arf(()),
                                data: report.as_ref(),
                            });
                            continue;
                        }

                        let subtype = part
                            .content_type()
                            .and_then(|ct| ct.subtype())
                            .unwrap_or("");
                        let attachment_name = part.attachment_name();
                        let ext = attachment_name
                            .and_then(|f| f.rsplit_once('.'))
                            .map_or("", |(_, e)| e);
                        let tls_parts = subtype.rsplit_once('+');
                        let compression = match (tls_parts.map(|(_, c)| c).unwrap_or(subtype), ext)
                        {
                            ("gzip", _) => Compression::Gzip,
                            ("zip", _) => Compression::Zip,
                            (_, "gz") => Compression::Gzip,
                            (_, "zip") => Compression::Zip,
                            _ => Compression::None,
                        };
                        let format = match (tls_parts.map(|(c, _)| c).unwrap_or(subtype), ext) {
                            ("xml", _) => Format::Dmarc(()),
                            ("tlsrpt", _) | (_, "json") => Format::Tls(()),
                            _ => {
                                if attachment_name
                                    .map_or(false, |n| n.contains(".xml") || n.contains('!'))
                                {
                                    Format::Dmarc(())
                                } else {
                                    continue;
                                }
                            }
                        };

                        reports.push(ReportData {
                            compression,
                            format,
                            data: report.as_ref(),
                        });
                    }
                    _ => (),
                }
            }

            for report in reports {
                let data = match report.compression {
                    Compression::None => Cow::Borrowed(report.data),
                    Compression::Gzip => {
                        let mut file = GzDecoder::new(report.data);
                        let mut buf = Vec::new();
                        if let Err(err) = file.read_to_end(&mut buf) {
                            trc::event!(
                                context = "report",
                                from = from,
                                "Failed to decompress report: {}",
                                err
                            );
                            continue;
                        }
                        Cow::Owned(buf)
                    }
                    Compression::Zip => {
                        let mut archive = match zip::ZipArchive::new(Cursor::new(report.data)) {
                            Ok(archive) => archive,
                            Err(err) => {
                                trc::event!(
                                    context = "report",
                                    from = from,
                                    "Failed to decompress report: {}",
                                    err
                                );
                                continue;
                            }
                        };
                        let mut buf = Vec::with_capacity(0);
                        for i in 0..archive.len() {
                            match archive.by_index(i) {
                                Ok(mut file) => {
                                    buf = Vec::with_capacity(file.compressed_size() as usize);
                                    if let Err(err) = file.read_to_end(&mut buf) {
                                        trc::event!(
                                            context = "report",
                                            from = from,
                                            "Failed to decompress report: {}",
                                            err
                                        );
                                    }
                                    break;
                                }
                                Err(err) => {
                                    trc::event!(
                                        context = "report",
                                        from = from,
                                        "Failed to decompress report: {}",
                                        err
                                    );
                                }
                            }
                        }
                        Cow::Owned(buf)
                    }
                };

                let report = match report.format {
                    Format::Dmarc(_) => match Report::parse_xml(&data) {
                        Ok(report) => {
                            // Send webhook
                            if core
                                .core
                                .has_webhook_subscribers(WebhookType::IncomingDmarcReport)
                            {
                                core.inner
                                    .ipc
                                    .send_webhook(
                                        WebhookType::IncomingDmarcReport,
                                        report.webhook_payload(),
                                    )
                                    .await;
                            }

                            // Log
                            report.log();
                            Format::Dmarc(report)
                        }
                        Err(err) => {
                            trc::event!(
                                context = "report",
                                from = from,
                                "Failed to parse DMARC report: {}",
                                err
                            );
                            continue;
                        }
                    },
                    Format::Tls(_) => match TlsReport::parse_json(&data) {
                        Ok(report) => {
                            // Send webhook
                            if core
                                .core
                                .has_webhook_subscribers(WebhookType::IncomingTlsReport)
                            {
                                core.inner
                                    .ipc
                                    .send_webhook(
                                        WebhookType::IncomingTlsReport,
                                        report.webhook_payload(),
                                    )
                                    .await;
                            }

                            // Log

                            report.log();
                            Format::Tls(report)
                        }
                        Err(err) => {
                            trc::event!(
                                context = "report",
                                from = from,
                                "Failed to parse TLS report: {:?}",
                                err
                            );
                            continue;
                        }
                    },
                    Format::Arf(_) => match Feedback::parse_arf(&data) {
                        Some(report) => {
                            // Send webhook
                            if core
                                .core
                                .has_webhook_subscribers(WebhookType::IncomingArfReport)
                            {
                                core.inner
                                    .ipc
                                    .send_webhook(
                                        WebhookType::IncomingArfReport,
                                        report.webhook_payload(),
                                    )
                                    .await;
                            }

                            // Log
                            report.log();
                            Format::Arf(report.into_owned())
                        }
                        None => {
                            trc::event!(
                                context = "report",
                                from = from,
                                "Failed to parse Auth Failure report"
                            );
                            continue;
                        }
                    },
                };

                // Store report
                if let Some(expires_in) = &core.core.smtp.report.analysis.store {
                    let expires = now() + expires_in.as_secs();
                    let id = core.inner.snowflake_id.generate().unwrap_or(expires);

                    let mut batch = BatchBuilder::new();
                    match report {
                        Format::Dmarc(report) => {
                            batch.set(
                                ValueClass::Report(ReportClass::Dmarc { id, expires }),
                                Bincode::new(IncomingReport {
                                    from,
                                    to,
                                    subject,
                                    report,
                                })
                                .serialize(),
                            );
                        }
                        Format::Tls(report) => {
                            batch.set(
                                ValueClass::Report(ReportClass::Tls { id, expires }),
                                Bincode::new(IncomingReport {
                                    from,
                                    to,
                                    subject,
                                    report,
                                })
                                .serialize(),
                            );
                        }
                        Format::Arf(report) => {
                            batch.set(
                                ValueClass::Report(ReportClass::Arf { id, expires }),
                                Bincode::new(IncomingReport {
                                    from,
                                    to,
                                    subject,
                                    report,
                                })
                                .serialize(),
                            );
                        }
                    }
                    let batch = batch.build();
                    if let Err(err) = core.core.storage.data.write(batch).await {
                        trc::event!(
                            context = "report",
                            event = "error",
                            "Failed to write incoming report: {}",
                            err
                        );
                    }
                }
                return;
            }
        });
    }
}

trait LogReport {
    fn log(&self);
    fn webhook_payload(&self) -> WebhookPayload;
}

impl LogReport for Report {
    fn log(&self) {
        let mut dmarc_pass = 0;
        let mut dmarc_quarantine = 0;
        let mut dmarc_reject = 0;
        let mut dmarc_none = 0;
        let mut dkim_pass = 0;
        let mut dkim_fail = 0;
        let mut dkim_none = 0;
        let mut spf_pass = 0;
        let mut spf_fail = 0;
        let mut spf_none = 0;

        for record in self.records() {
            let count = std::cmp::min(record.count(), 1);

            match record.action_disposition() {
                ActionDisposition::Pass => {
                    dmarc_pass += count;
                }
                ActionDisposition::Quarantine => {
                    dmarc_quarantine += count;
                }
                ActionDisposition::Reject => {
                    dmarc_reject += count;
                }
                ActionDisposition::None | ActionDisposition::Unspecified => {
                    dmarc_none += count;
                }
            }
            match record.dmarc_dkim_result() {
                DmarcResult::Pass => {
                    dkim_pass += count;
                }
                DmarcResult::Fail => {
                    dkim_fail += count;
                }
                DmarcResult::Unspecified => {
                    dkim_none += count;
                }
            }
            match record.dmarc_spf_result() {
                DmarcResult::Pass => {
                    spf_pass += count;
                }
                DmarcResult::Fail => {
                    spf_fail += count;
                }
                DmarcResult::Unspecified => {
                    spf_none += count;
                }
            }
        }

        let range_from = DateTime::from_timestamp(self.date_range_begin() as i64).to_rfc3339();
        let range_to = DateTime::from_timestamp(self.date_range_end() as i64).to_rfc3339();

        if (dmarc_reject + dmarc_quarantine + dkim_fail + spf_fail) > 0 {
            trc::event!(
                context = "dmarc",
                event = "analyze",
                range_from = range_from,
                range_to = range_to,
                domain = self.domain(),
                report_email = self.email(),
                report_id = self.report_id(),
                dmarc_pass = dmarc_pass,
                dmarc_quarantine = dmarc_quarantine,
                dmarc_reject = dmarc_reject,
                dmarc_none = dmarc_none,
                dkim_pass = dkim_pass,
                dkim_fail = dkim_fail,
                dkim_none = dkim_none,
                spf_pass = spf_pass,
                spf_fail = spf_fail,
                spf_none = spf_none,
            );
        } else {
            trc::event!(
                context = "dmarc",
                event = "analyze",
                range_from = range_from,
                range_to = range_to,
                domain = self.domain(),
                report_email = self.email(),
                report_id = self.report_id(),
                dmarc_pass = dmarc_pass,
                dmarc_quarantine = dmarc_quarantine,
                dmarc_reject = dmarc_reject,
                dmarc_none = dmarc_none,
                dkim_pass = dkim_pass,
                dkim_fail = dkim_fail,
                dkim_none = dkim_none,
                spf_pass = spf_pass,
                spf_fail = spf_fail,
                spf_none = spf_none,
            );
        }
    }

    fn webhook_payload(&self) -> WebhookPayload {
        let mut dmarc_pass = 0;
        let mut dmarc_quarantine = 0;
        let mut dmarc_reject = 0;
        let mut dmarc_none = 0;
        let mut dkim_pass = 0;
        let mut dkim_fail = 0;
        let mut dkim_none = 0;
        let mut spf_pass = 0;
        let mut spf_fail = 0;
        let mut spf_none = 0;

        for record in self.records() {
            let count = std::cmp::min(record.count(), 1);

            match record.action_disposition() {
                ActionDisposition::Pass => {
                    dmarc_pass += count;
                }
                ActionDisposition::Quarantine => {
                    dmarc_quarantine += count;
                }
                ActionDisposition::Reject => {
                    dmarc_reject += count;
                }
                ActionDisposition::None | ActionDisposition::Unspecified => {
                    dmarc_none += count;
                }
            }
            match record.dmarc_dkim_result() {
                DmarcResult::Pass => {
                    dkim_pass += count;
                }
                DmarcResult::Fail => {
                    dkim_fail += count;
                }
                DmarcResult::Unspecified => {
                    dkim_none += count;
                }
            }
            match record.dmarc_spf_result() {
                DmarcResult::Pass => {
                    spf_pass += count;
                }
                DmarcResult::Fail => {
                    spf_fail += count;
                }
                DmarcResult::Unspecified => {
                    spf_none += count;
                }
            }
        }

        let range_from = DateTime::from_timestamp(self.date_range_begin() as i64).to_rfc3339();
        let range_to = DateTime::from_timestamp(self.date_range_end() as i64).to_rfc3339();

        WebhookPayload::IncomingDmarcReport {
            range_from,
            range_to,
            domain: self.domain().to_string(),
            report_email: self.email().to_string(),
            report_id: self.report_id().to_string(),
            dmarc_pass,
            dmarc_quarantine,
            dmarc_reject,
            dmarc_none,
            dkim_pass,
            dkim_fail,
            dkim_none,
            spf_pass,
            spf_fail,
            spf_none,
        }
    }
}

impl LogReport for TlsReport {
    fn log(&self) {
        for policy in self.policies.iter().take(5) {
            let mut details = AHashMap::with_capacity(policy.failure_details.len());
            for failure in &policy.failure_details {
                let num_failures = std::cmp::min(1, failure.failed_session_count);
                match details.entry(failure.result_type) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += num_failures;
                    }
                    Entry::Vacant(e) => {
                        e.insert(num_failures);
                    }
                }
            }

            if policy.summary.total_failure > 0 {
                trc::event!(
                    context = "tlsrpt",
                    event = "analyze",
                    range_from = self.date_range.start_datetime.to_rfc3339(),
                    range_to = self.date_range.end_datetime.to_rfc3339(),
                    domain = policy.policy.policy_domain,
                    report_contact = self.contact_info.as_deref().unwrap_or("unknown"),
                    report_id = self.report_id,
                    policy_type = ?policy.policy.policy_type,
                    total_success = policy.summary.total_success,
                    total_failures = policy.summary.total_failure,
                    details = ?details,
                );
            } else {
                trc::event!(
                    context = "tlsrpt",
                    event = "analyze",
                    range_from = self.date_range.start_datetime.to_rfc3339(),
                    range_to = self.date_range.end_datetime.to_rfc3339(),
                    domain = policy.policy.policy_domain,
                    report_contact = self.contact_info.as_deref().unwrap_or("unknown"),
                    report_id = self.report_id,
                    policy_type = ?policy.policy.policy_type,
                    total_success = policy.summary.total_success,
                    total_failures = policy.summary.total_failure,
                    details = ?details,
                );
            }
        }
    }

    fn webhook_payload(&self) -> WebhookPayload {
        let mut policies = Vec::with_capacity(self.policies.len());

        for policy in self.policies.iter().take(5) {
            let mut details = AHashMap::with_capacity(policy.failure_details.len());
            for failure in &policy.failure_details {
                let num_failures = std::cmp::min(1, failure.failed_session_count);
                match details.entry(failure.result_type) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += num_failures;
                    }
                    Entry::Vacant(e) => {
                        e.insert(num_failures);
                    }
                }
            }

            policies.push(WebhookTlsPolicy {
                range_from: self.date_range.start_datetime.to_rfc3339(),
                range_to: self.date_range.end_datetime.to_rfc3339(),
                domain: policy.policy.policy_domain.clone(),
                report_contact: self.contact_info.clone(),
                report_id: self.report_id.clone(),
                policy_type: policy.policy.policy_type,
                total_successes: policy.summary.total_success,
                total_failures: policy.summary.total_failure,
                details,
            });
        }

        WebhookPayload::IncomingTlsReport { policies }
    }
}

impl LogReport for Feedback<'_> {
    fn log(&self) {
        trc::event!(
            context = "arf",
            event = "analyze",
            feedback_type = ?self.feedback_type(),
            arrival_date = DateTime::from_timestamp(self.arrival_date().unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64
            })).to_rfc3339(),
            authentication_results = ?self.authentication_results(),
            incidents = self.incidents(),
            reported_domain = ?self.reported_domain(),
            reported_uri = ?self.reported_uri(),
            reporting_mta = self.reporting_mta().unwrap_or_default(),
            source_ip = ?self.source_ip(),
            user_agent = self.user_agent().unwrap_or_default(),
            auth_failure = ?self.auth_failure(),
            delivery_result = ?self.delivery_result(),
            dkim_domain = self.dkim_domain().unwrap_or_default(),
            dkim_identity = self.dkim_identity().unwrap_or_default(),
            dkim_selector = self.dkim_selector().unwrap_or_default(),
            identity_alignment = ?self.identity_alignment(),
        );
    }

    fn webhook_payload(&self) -> WebhookPayload {
        WebhookPayload::IncomingArfReport {
            feedback_type: self.feedback_type(),
            arrival_date: self
                .arrival_date()
                .map(|a| DateTime::from_timestamp(a).to_rfc3339()),
            authentication_results: self
                .authentication_results()
                .iter()
                .map(|t| t.to_string())
                .collect(),
            incidents: self.incidents(),
            reported_domain: self
                .reported_domain()
                .iter()
                .map(|t| t.to_string())
                .collect(),
            reported_uri: self.reported_uri().iter().map(|t| t.to_string()).collect(),
            reporting_mta: self.reporting_mta().map(|t| t.to_string()),
            source_ip: self.source_ip(),
            user_agent: self.user_agent().map(|t| t.to_string()),
            auth_failure: self.auth_failure(),
            delivery_result: self.delivery_result(),
            dkim_domain: self.dkim_domain().map(|t| t.to_string()),
            dkim_identity: self.dkim_identity().map(|t| t.to_string()),
            dkim_selector: self.dkim_selector().map(|t| t.to_string()),
            identity_alignment: self.identity_alignment(),
        }
    }
}
