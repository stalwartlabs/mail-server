/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AggregateTimestamp, SerializedSize};
use crate::{queue::RecipientDomain, reporting::SmtpReporting};
use ahash::AHashMap;
use common::{
    Server,
    config::smtp::{
        report::AggregateFrequency,
        resolver::{Mode, MxPattern},
    },
    ipc::{TlsEvent, ToHash},
};
use mail_auth::{
    flate2::{Compression, write::GzEncoder},
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::{
        DateRange, FailureDetails, Policy, PolicyDetails, PolicyType, Summary, TlsReport,
    },
};
use mail_parser::DateTime;
use reqwest::header::CONTENT_TYPE;
use std::fmt::Write;
use std::{collections::hash_map::Entry, future::Future, sync::Arc, time::Duration};
use store::{
    Deserialize, IterateParams, Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, ReportEvent, ValueClass},
};
use trc::{AddContext, OutgoingReportEvent};

#[derive(Debug, Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, serde::Serialize)]
pub struct TlsFormat {
    pub rua: Vec<ReportUri>,
    pub policy: PolicyDetails,
    pub records: Vec<Option<FailureDetails>>,
}

#[cfg(feature = "test_mode")]
pub static TLS_HTTP_REPORT: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

pub trait TlsReporting: Sync + Send {
    fn send_tls_aggregate_report(
        &self,
        events: Vec<ReportEvent>,
    ) -> impl Future<Output = ()> + Send;
    fn generate_tls_aggregate_report(
        &self,
        events: &[ReportEvent],
        rua: &mut Vec<ReportUri>,
        serialized_size: Option<&mut serde_json::Serializer<SerializedSize>>,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<Option<TlsReport>>> + Send;
    fn schedule_tls(&self, event: Box<TlsEvent>) -> impl Future<Output = ()> + Send;
    fn delete_tls_report(&self, events: Vec<ReportEvent>) -> impl Future<Output = ()> + Send;
}

impl TlsReporting for Server {
    async fn send_tls_aggregate_report(&self, events: Vec<ReportEvent>) {
        let (domain_name, event_from, event_to) = events
            .first()
            .map(|e| (e.domain.as_str(), e.seq_id, e.due))
            .unwrap();

        let span_id = self.inner.data.span_id_gen.generate();

        trc::event!(
            OutgoingReport(OutgoingReportEvent::TlsAggregate),
            SpanId = span_id,
            ReportId = event_from,
            Domain = domain_name.to_string(),
            RangeFrom = trc::Value::Timestamp(event_from),
            RangeTo = trc::Value::Timestamp(event_to),
        );

        // Generate report
        let mut rua = Vec::new();
        let mut serialized_size = serde_json::Serializer::new(SerializedSize::new(
            self.eval_if(
                &self.core.smtp.report.tls.max_size,
                &RecipientDomain::new(domain_name),
                span_id,
            )
            .await
            .unwrap_or(25 * 1024 * 1024),
        ));
        let report = match self
            .generate_tls_aggregate_report(&events, &mut rua, Some(&mut serialized_size), span_id)
            .await
        {
            Ok(Some(report)) => report,
            Ok(None) => {
                // This should not happen
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::NotFound),
                    SpanId = span_id,
                    CausedBy = trc::location!()
                );
                self.delete_tls_report(events).await;
                return;
            }
            Err(err) => {
                trc::error!(
                    err.span_id(span_id)
                        .caused_by(trc::location!())
                        .details("Failed to read TLS report")
                );
                return;
            }
        };

        // Compress and serialize report
        let json = report.to_json();
        let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
        let json = match std::io::Write::write_all(&mut e, json.as_bytes()).and_then(|_| e.finish())
        {
            Ok(report) => report,
            Err(err) => {
                trc::event!(
                    OutgoingReport(OutgoingReportEvent::SubmissionError),
                    SpanId = span_id,
                    Reason = err.to_string(),
                    Details = "Failed to compress report"
                );

                self.delete_tls_report(events).await;
                return;
            }
        };

        // Try delivering report over HTTP
        let mut rcpts = Vec::with_capacity(rua.len());
        for uri in &rua {
            match uri {
                ReportUri::Http(uri) => {
                    if let Ok(client) = utils::reqwest_client_builder()
                        .timeout(Duration::from_secs(2 * 60))
                        .build()
                    {
                        #[cfg(feature = "test_mode")]
                        if uri == "https://127.0.0.1/tls" {
                            TLS_HTTP_REPORT.lock().extend_from_slice(&json);
                            self.delete_tls_report(events).await;
                            return;
                        }

                        match client
                            .post(uri)
                            .header(CONTENT_TYPE, "application/tlsrpt+gzip")
                            .body(json.to_vec())
                            .send()
                            .await
                        {
                            Ok(response) => {
                                if response.status().is_success() {
                                    trc::event!(
                                        OutgoingReport(OutgoingReportEvent::HttpSubmission),
                                        SpanId = span_id,
                                        Url = uri.to_string(),
                                        Code = response.status().as_u16(),
                                    );

                                    self.delete_tls_report(events).await;
                                    return;
                                } else {
                                    trc::event!(
                                        OutgoingReport(OutgoingReportEvent::SubmissionError),
                                        SpanId = span_id,
                                        Url = uri.to_string(),
                                        Code = response.status().as_u16(),
                                        Details = "Invalid HTTP response"
                                    );
                                }
                            }
                            Err(err) => {
                                trc::event!(
                                    OutgoingReport(OutgoingReportEvent::SubmissionError),
                                    SpanId = span_id,
                                    Url = uri.to_string(),
                                    Reason = err.to_string(),
                                    Details = "HTTP submission error"
                                );
                            }
                        }
                    }
                }
                ReportUri::Mail(mailto) => {
                    rcpts.push(mailto.as_str());
                }
            }
        }

        // Deliver report over SMTP
        if !rcpts.is_empty() {
            let config = &self.core.smtp.report.tls;
            let from_addr = self
                .eval_if(&config.address, &RecipientDomain::new(domain_name), span_id)
                .await
                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
            let mut message = Vec::with_capacity(2048);
            let _ = report.write_rfc5322_from_bytes(
                domain_name,
                &self
                    .eval_if(
                        &self.core.smtp.report.submitter,
                        &RecipientDomain::new(domain_name),
                        span_id,
                    )
                    .await
                    .unwrap_or_else(|| "localhost".to_string()),
                (
                    self.eval_if(&config.name, &RecipientDomain::new(domain_name), span_id)
                        .await
                        .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpts.iter().copied(),
                &json,
                &mut message,
            );

            // Send report
            self.send_report(
                &from_addr,
                rcpts.iter(),
                message,
                &config.sign,
                false,
                span_id,
            )
            .await;
        } else {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::NoRecipientsFound),
                SpanId = span_id,
            );
        }
        self.delete_tls_report(events).await;
    }

    async fn generate_tls_aggregate_report(
        &self,
        events: &[ReportEvent],
        rua: &mut Vec<ReportUri>,
        mut serialized_size: Option<&mut serde_json::Serializer<SerializedSize>>,
        span_id: u64,
    ) -> trc::Result<Option<TlsReport>> {
        let (domain_name, event_from, event_to, policy) = events
            .first()
            .map(|e| (e.domain.as_str(), e.seq_id, e.due, e.policy_hash))
            .unwrap();
        let config = &self.core.smtp.report.tls;
        let mut report = TlsReport {
            organization_name: self
                .eval_if::<String, _>(
                    &config.org_name,
                    &RecipientDomain::new(domain_name),
                    span_id,
                )
                .await
                .clone(),
            date_range: DateRange {
                start_datetime: DateTime::from_timestamp(event_from as i64),
                end_datetime: DateTime::from_timestamp(event_to as i64),
            },
            contact_info: self
                .eval_if::<String, _>(
                    &config.contact_info,
                    &RecipientDomain::new(domain_name),
                    span_id,
                )
                .await
                .clone(),
            report_id: format!("{}_{}", event_from, policy),
            policies: Vec::with_capacity(events.len()),
        };

        if let Some(serialized_size) = serialized_size.as_deref_mut() {
            let _ = serde::Serialize::serialize(&report, serialized_size);
        }

        for event in events {
            let tls = if let Some(tls) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                    QueueClass::TlsReportHeader(event.clone()),
                )))
                .await?
            {
                tls.deserialize::<TlsFormat>()?
            } else {
                continue;
            };

            if let Some(serialized_size) = serialized_size.as_deref_mut() {
                if serde::Serialize::serialize(&tls, serialized_size).is_err() {
                    continue;
                }
            }

            // Group duplicates
            let mut total_success = 0;
            let mut total_failure = 0;
            let from_key =
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: event.due,
                    policy_hash: event.policy_hash,
                    seq_id: 0,
                    domain: event.domain.clone(),
                })));
            let to_key =
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: event.due,
                    policy_hash: event.policy_hash,
                    seq_id: u64::MAX,
                    domain: event.domain.clone(),
                })));
            let mut record_map = AHashMap::new();
            self.core
                .storage
                .data
                .iterate(IterateParams::new(from_key, to_key).ascending(), |_, v| {
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(v)?;
                    if let Some(failure_details) =
                        archive.deserialize::<Option<FailureDetails>>()?
                    {
                        match record_map.entry(failure_details) {
                            Entry::Occupied(mut e) => {
                                total_failure += 1;
                                *e.get_mut() += 1;
                                Ok(true)
                            }
                            Entry::Vacant(e) => {
                                if serialized_size
                                    .as_deref_mut()
                                    .is_none_or(|serialized_size| {
                                        serde::Serialize::serialize(e.key(), serialized_size)
                                            .is_ok()
                                    })
                                {
                                    total_failure += 1;
                                    e.insert(1u32);
                                    Ok(true)
                                } else {
                                    Ok(false)
                                }
                            }
                        }
                    } else {
                        total_success += 1;
                        Ok(true)
                    }
                })
                .await
                .caused_by(trc::location!())?;

            // Add policy
            report.policies.push(Policy {
                policy: tls.policy,
                summary: Summary {
                    total_success,
                    total_failure,
                },
                failure_details: record_map
                    .into_iter()
                    .map(|(mut r, count)| {
                        r.failed_session_count = count;
                        r
                    })
                    .collect(),
            });

            // Add report URIs
            for entry in tls.rua {
                if !rua.contains(&entry) {
                    rua.push(entry);
                }
            }
        }

        Ok(if !report.policies.is_empty() {
            Some(report)
        } else {
            None
        })
    }

    async fn schedule_tls(&self, event: Box<TlsEvent>) {
        let created = event.interval.to_timestamp();
        let deliver_at = created + event.interval.as_secs();
        let mut report_event = ReportEvent {
            due: deliver_at,
            policy_hash: event.policy.to_hash(),
            seq_id: created,
            domain: event.domain,
        };

        // Write policy if missing
        let mut builder = BatchBuilder::new();
        if self
            .core
            .storage
            .data
            .get_value::<()>(ValueKey::from(ValueClass::Queue(
                QueueClass::TlsReportHeader(report_event.clone()),
            )))
            .await
            .unwrap_or_default()
            .is_none()
        {
            // Serialize report
            let mut policy = PolicyDetails {
                policy_type: PolicyType::NoPolicyFound,
                policy_string: vec![],
                policy_domain: report_event.domain.clone(),
                mx_host: vec![],
            };

            match event.policy {
                common::ipc::PolicyType::Tlsa(tlsa) => {
                    policy.policy_type = PolicyType::Tlsa;
                    if let Some(tlsa) = tlsa {
                        for entry in &tlsa.entries {
                            policy.policy_string.push(format!(
                                "{} {} {} {}",
                                if entry.is_end_entity { 3 } else { 2 },
                                i32::from(entry.is_spki),
                                if entry.is_sha256 { 1 } else { 2 },
                                entry
                                    .data
                                    .iter()
                                    .fold(String::with_capacity(64), |mut s, b| {
                                        write!(s, "{b:02X}").ok();
                                        s
                                    })
                            ));
                        }
                    }
                }
                common::ipc::PolicyType::Sts(sts) => {
                    policy.policy_type = PolicyType::Sts;
                    if let Some(sts) = sts {
                        policy.policy_string.push("version: STSv1".to_string());
                        policy.policy_string.push(format!(
                            "mode: {}",
                            match sts.mode {
                                Mode::Enforce => "enforce",
                                Mode::Testing => "testing",
                                Mode::None => "none",
                            }
                        ));
                        policy
                            .policy_string
                            .push(format!("max_age: {}", sts.max_age));
                        for mx in &sts.mx {
                            let mx = match mx {
                                MxPattern::Equals(mx) => mx.to_string(),
                                MxPattern::StartsWith(mx) => format!("*.{mx}"),
                            };
                            policy.policy_string.push(format!("mx: {mx}"));
                            policy.mx_host.push(mx);
                        }
                    }
                }
                _ => (),
            }

            // Create report entry
            let entry = TlsFormat {
                rua: event.tls_record.rua.clone(),
                policy,
                records: vec![],
            };

            // Write report
            builder.set(
                ValueClass::Queue(QueueClass::TlsReportHeader(report_event.clone())),
                match Archiver::new(entry).serialize() {
                    Ok(data) => data.to_vec(),
                    Err(err) => {
                        trc::error!(
                            err.caused_by(trc::location!())
                                .details("Failed to serialize TLS report")
                        );
                        return;
                    }
                },
            );
        }

        // Write entry
        report_event.seq_id = self.inner.data.queue_id_gen.generate();
        builder.set(
            ValueClass::Queue(QueueClass::TlsReportEvent(report_event)),
            match Archiver::new(event.failure).serialize() {
                Ok(data) => data.to_vec(),
                Err(err) => {
                    trc::error!(
                        err.caused_by(trc::location!())
                            .details("Failed to serialize TLS report")
                    );
                    return;
                }
            },
        );

        if let Err(err) = self.core.storage.data.write(builder.build_all()).await {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to write TLS report")
            );
        }
    }

    async fn delete_tls_report(&self, events: Vec<ReportEvent>) {
        let mut batch = BatchBuilder::new();

        for event in events {
            let from_key = ReportEvent {
                due: event.due,
                policy_hash: event.policy_hash,
                seq_id: 0,
                domain: event.domain.clone(),
            };
            let to_key = ReportEvent {
                due: event.due,
                policy_hash: event.policy_hash,
                seq_id: u64::MAX,
                domain: event.domain.clone(),
            };

            // Remove report events
            if let Err(err) = self
                .core
                .storage
                .data
                .delete_range(
                    ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(from_key))),
                    ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(to_key))),
                )
                .await
            {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to delete TLS reports")
                );

                return;
            }

            // Remove report header
            batch.clear(ValueClass::Queue(QueueClass::TlsReportHeader(event)));
        }

        if let Err(err) = self.core.storage.data.write(batch.build_all()).await {
            trc::error!(
                err.caused_by(trc::location!())
                    .details("Failed to delete TLS reports")
            );
        }
    }
}
