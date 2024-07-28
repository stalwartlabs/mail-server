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
};

use ahash::AHashMap;
use mail_auth::{
    flate2::read::GzDecoder,
    report::{tlsrpt::TlsReport, ActionDisposition, DmarcResult, Feedback, Report},
    zip,
};
use mail_parser::{MessageParser, MimeHeaders, PartType};

use store::{
    write::{now, BatchBuilder, Bincode, ReportClass, ValueClass},
    Serialize,
};
use trc::IncomingReportEvent;

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
    pub fn analyze_report(&self, message: Arc<Vec<u8>>, session_id: u64) {
        let core = self.clone();
        tokio::spawn(async move {
            let message = if let Some(message) = MessageParser::default().parse(message.as_ref()) {
                message
            } else {
                trc::event!(
                    IncomingReport(IncomingReportEvent::MessageParseFailed),
                    SpanId = session_id
                );

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
                                IncomingReport(IncomingReportEvent::DecompressError),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = err.to_string(),
                                CausedBy = trc::location!()
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
                                    IncomingReport(IncomingReportEvent::DecompressError),
                                    SpanId = session_id,
                                    From = from.to_string(),
                                    Reason = err.to_string(),
                                    CausedBy = trc::location!()
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
                                            IncomingReport(IncomingReportEvent::DecompressError),
                                            SpanId = session_id,
                                            From = from.to_string(),
                                            Reason = err.to_string(),
                                            CausedBy = trc::location!()
                                        );
                                    }
                                    break;
                                }
                                Err(err) => {
                                    trc::event!(
                                        IncomingReport(IncomingReportEvent::DecompressError),
                                        SpanId = session_id,
                                        From = from.to_string(),
                                        Reason = err.to_string(),
                                        CausedBy = trc::location!()
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
                            // Log
                            report.log();
                            Format::Dmarc(report)
                        }
                        Err(err) => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::DmarcParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = err,
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                    },
                    Format::Tls(_) => match TlsReport::parse_json(&data) {
                        Ok(report) => {
                            // Log
                            report.log();
                            Format::Tls(report)
                        }
                        Err(err) => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::TlsRpcParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                Reason = format!("{err:?}"),
                                CausedBy = trc::location!()
                            );

                            continue;
                        }
                    },
                    Format::Arf(_) => match Feedback::parse_arf(&data) {
                        Some(report) => {
                            // Log
                            report.log();
                            Format::Arf(report.into_owned())
                        }
                        None => {
                            trc::event!(
                                IncomingReport(IncomingReportEvent::ArfParseFailed),
                                SpanId = session_id,
                                From = from.to_string(),
                                CausedBy = trc::location!()
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
                        trc::error!(err
                            .span_id(session_id)
                            .caused_by(trc::location!())
                            .details("Failed to write report"));
                    }
                }
                return;
            }
        });
    }
}

trait LogReport {
    fn log(&self);
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

        trc::event!(
            IncomingReport(
                if (dmarc_reject + dmarc_quarantine + dkim_fail + spf_fail) > 0 {
                    IncomingReportEvent::DmarcReportWithWarnings
                } else {
                    IncomingReportEvent::DmarcReport
                }
            ),
            RangeFrom = trc::Value::Timestamp(self.date_range_begin()),
            RangeTo = trc::Value::Timestamp(self.date_range_end()),
            Domain = self.domain().to_string(),
            From = self.email().to_string(),
            Id = self.report_id().to_string(),
            DmarcPass = dmarc_pass,
            DmarcQuarantine = dmarc_quarantine,
            DmarcReject = dmarc_reject,
            DmarcNone = dmarc_none,
            DkimPass = dkim_pass,
            DkimFail = dkim_fail,
            DkimNone = dkim_none,
            SpfPass = spf_pass,
            SpfFail = spf_fail,
            SpfNone = spf_none,
        );
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

            trc::event!(
                IncomingReport(if policy.summary.total_failure > 0 {
                    IncomingReportEvent::TlsReportWithWarnings
                } else {
                    IncomingReportEvent::TlsReport
                }),
                RangeFrom =
                    trc::Value::Timestamp(self.date_range.start_datetime.to_timestamp() as u64),
                RangeTo = trc::Value::Timestamp(self.date_range.end_datetime.to_timestamp() as u64),
                Domain = policy.policy.policy_domain.clone(),
                From = self.contact_info.as_deref().unwrap_or_default().to_string(),
                Id = self.report_id.clone(),
                PolicyType = format!("{:?}", policy.policy.policy_type),
                TotalSuccesses = policy.summary.total_success,
                TotalFailures = policy.summary.total_failure,
                Details = format!("{details:?}"),
            );
        }
    }
}

impl LogReport for Feedback<'_> {
    fn log(&self) {
        let rt = match self.feedback_type() {
            mail_auth::report::FeedbackType::Abuse => IncomingReportEvent::AbuseReport,
            mail_auth::report::FeedbackType::AuthFailure => IncomingReportEvent::AuthFailureReport,
            mail_auth::report::FeedbackType::Fraud => IncomingReportEvent::FraudReport,
            mail_auth::report::FeedbackType::NotSpam => IncomingReportEvent::NotSpamReport,
            mail_auth::report::FeedbackType::Other => IncomingReportEvent::OtherReport,
            mail_auth::report::FeedbackType::Virus => IncomingReportEvent::VirusReport,
        };

        /*

           user_agent = self.user_agent().unwrap_or_default(),
           auth_failure = ?self.auth_failure(),
           dkim_domain = self.dkim_domain().unwrap_or_default(),
           dkim_identity = self.dkim_identity().unwrap_or_default(),
           dkim_selector = self.dkim_selector().unwrap_or_default(),
           identity_alignment = ?self.identity_alignment(),

        */

        trc::event!(
            IncomingReport(rt),
            Date = trc::Value::Timestamp(
                self.arrival_date()
                    .map(|d| d as u64)
                    .unwrap_or_else(|| { now() })
            ),
            Domain = self
                .reported_domain()
                .iter()
                .map(|d| trc::Value::String(d.to_string()))
                .collect::<Vec<_>>(),
            Hostname = self
                .reporting_mta()
                .map(|d| trc::Value::String(d.to_string())),
            Url = self
                .reported_uri()
                .iter()
                .map(|d| trc::Value::String(d.to_string()))
                .collect::<Vec<_>>(),
            RemoteIp = self.source_ip(),
            Count = self.incidents(),
            Result = format!("{:?}", self.delivery_result()),
            Details = self
                .authentication_results()
                .iter()
                .map(|d| trc::Value::String(d.to_string()))
                .collect::<Vec<_>>(),
        );
    }
}
