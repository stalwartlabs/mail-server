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

use std::{collections::hash_map::Entry, path::PathBuf, sync::Arc, time::Duration};

use ahash::AHashMap;
use mail_auth::{
    flate2::{write::GzEncoder, Compression},
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::{
        DateRange, FailureDetails, Policy, PolicyDetails, PolicyType, Summary, TlsReport,
    },
};

use mail_parser::DateTime;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use tokio::runtime::Handle;

use crate::{
    config::AggregateFrequency,
    core::SMTP,
    outbound::mta_sts::{Mode, MxPattern},
    queue::{InstantFromTimestamp, RecipientDomain, Schedule},
    USER_AGENT,
};

use super::{
    scheduler::{
        json_append, json_read_blocking, json_write, ReportPath, ReportPolicy, ReportType,
        Scheduler, ToHash,
    },
    TlsEvent,
};

#[derive(Debug, Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, Serialize, Deserialize)]
struct TlsFormat {
    rua: Vec<ReportUri>,
    policy: PolicyDetails,
    records: Vec<Option<FailureDetails>>,
}

pub trait GenerateTlsReport {
    fn generate_tls_report(&self, domain: String, paths: ReportPath<Vec<ReportPolicy<PathBuf>>>);
}

#[cfg(feature = "test_mode")]
pub static TLS_HTTP_REPORT: parking_lot::Mutex<Vec<u8>> = parking_lot::Mutex::new(Vec::new());

impl GenerateTlsReport for Arc<SMTP> {
    fn generate_tls_report(&self, domain: String, path: ReportPath<Vec<ReportPolicy<PathBuf>>>) {
        let core = self.clone();
        let handle = Handle::current();

        self.worker_pool.spawn(move || {
            let deliver_at = path.created + path.deliver_at.as_secs();
            let span = tracing::info_span!(
                "tls-report",
                domain = domain,
                range_from = path.created,
                range_to = deliver_at,
                size = path.size,
            );

            // Deserialize report
            let config = &core.report.config.tls;
            let mut report = TlsReport {
                organization_name: handle
                    .block_on(
                        core.eval_if(&config.org_name, &RecipientDomain::new(domain.as_str())),
                    )
                    .clone(),
                date_range: DateRange {
                    start_datetime: DateTime::from_timestamp(path.created as i64),
                    end_datetime: DateTime::from_timestamp(deliver_at as i64),
                },
                contact_info: handle
                    .block_on(
                        core.eval_if(&config.contact_info, &RecipientDomain::new(domain.as_str())),
                    )
                    .clone(),
                report_id: format!(
                    "{}_{}",
                    path.created,
                    path.path.first().map_or(0, |p| p.policy)
                ),
                policies: Vec::with_capacity(path.path.len()),
            };
            let mut rua = Vec::new();
            for path in &path.path {
                if let Some(tls) = json_read_blocking::<TlsFormat>(&path.inner, &span) {
                    // Group duplicates
                    let mut total_success = 0;
                    let mut total_failure = 0;
                    let mut record_map = AHashMap::with_capacity(tls.records.len());
                    for record in tls.records {
                        if let Some(record) = record {
                            match record_map.entry(record) {
                                Entry::Occupied(mut e) => {
                                    *e.get_mut() += 1;
                                }
                                Entry::Vacant(e) => {
                                    e.insert(1u32);
                                }
                            }
                            total_failure += 1;
                        } else {
                            total_success += 1;
                        }
                    }
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

                    rua = tls.rua;
                }
            }

            if report.policies.is_empty() {
                // This should not happen
                tracing::warn!(
                    parent: &span,
                    event = "empty-report",
                    "No policies found in report"
                );
                path.cleanup_blocking();
                return;
            }

            // Compress and serialize report
            let json = report.to_json();
            let mut e = GzEncoder::new(Vec::with_capacity(json.len()), Compression::default());
            let json =
                match std::io::Write::write_all(&mut e, json.as_bytes()).and_then(|_| e.finish()) {
                    Ok(report) => report,
                    Err(err) => {
                        tracing::error!(
                            parent: &span,
                            event = "error",
                            "Failed to compress report: {}",
                            err
                        );
                        return;
                    }
                };

            // Try delivering report over HTTP
            let mut rcpts = Vec::with_capacity(rua.len());
            for uri in &rua {
                match uri {
                    ReportUri::Http(uri) => {
                        if let Ok(client) = reqwest::blocking::Client::builder()
                            .user_agent(USER_AGENT)
                            .timeout(Duration::from_secs(2 * 60))
                            .build()
                        {
                            #[cfg(feature = "test_mode")]
                            if uri == "https://127.0.0.1/tls" {
                                TLS_HTTP_REPORT.lock().extend_from_slice(&json);
                                path.cleanup_blocking();
                                return;
                            }

                            match client
                                .post(uri)
                                .header(CONTENT_TYPE, "application/tlsrpt+gzip")
                                .body(json.to_vec())
                                .send()
                            {
                                Ok(response) => {
                                    if response.status().is_success() {
                                        tracing::info!(
                                            parent: &span,
                                            context = "http",
                                            event = "success",
                                            url = uri,
                                        );
                                        path.cleanup_blocking();
                                        return;
                                    } else {
                                        tracing::debug!(
                                            parent: &span,
                                            context = "http",
                                            event = "invalid-response",
                                            url = uri,
                                            status = %response.status()
                                        );
                                    }
                                }
                                Err(err) => {
                                    tracing::debug!(
                                        parent: &span,
                                        context = "http",
                                        event = "error",
                                        url = uri,
                                        reason = %err
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
                let from_addr = handle
                    .block_on(core.eval_if(&config.address, &RecipientDomain::new(domain.as_str())))
                    .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
                let mut message = Vec::with_capacity(path.size);
                let _ = report.write_rfc5322_from_bytes(
                    &domain,
                    &handle
                        .block_on(core.eval_if(
                            &core.report.config.submitter,
                            &RecipientDomain::new(domain.as_str()),
                        ))
                        .unwrap_or_else(|| "localhost".to_string()),
                    (
                        handle
                            .block_on(
                                core.eval_if(&config.name, &RecipientDomain::new(domain.as_str())),
                            )
                            .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                            .as_str(),
                        from_addr.as_str(),
                    ),
                    rcpts.iter().copied(),
                    &json,
                    &mut message,
                );

                // Send report
                handle.block_on(core.send_report(
                    &from_addr,
                    rcpts.iter(),
                    message,
                    &config.sign,
                    &span,
                    false,
                ));
            } else {
                tracing::info!(
                    parent: &span,
                    event = "delivery-failed",
                    "No valid recipients found to deliver report to."
                );
            }
            path.cleanup_blocking();
        });
    }
}

impl Scheduler {
    pub async fn schedule_tls(&mut self, event: Box<TlsEvent>, core: &SMTP) {
        let max_size = core
            .eval_if(
                &core.report.config.tls.max_size,
                &RecipientDomain::new(event.domain.as_str()),
            )
            .await
            .unwrap_or(25 * 1024 * 1024);
        let policy_hash = event.policy.to_hash();

        let (path, pos, create) = match self.reports.entry(ReportType::Tls(event.domain)) {
            Entry::Occupied(e) => {
                if let ReportType::Tls(path) = e.get() {
                    if let Some(pos) = path.path.iter().position(|p| p.policy == policy_hash) {
                        (e.into_mut().tls_path(), pos, None)
                    } else {
                        let pos = path.path.len();
                        let domain = e.key().domain_name().to_string();
                        let path = e.into_mut().tls_path();
                        path.path.push(ReportPolicy {
                            inner: core
                                .build_report_path(
                                    ReportType::Tls(&domain),
                                    policy_hash,
                                    path.created,
                                    path.deliver_at,
                                )
                                .await,
                            policy: policy_hash,
                        });
                        (path, pos, domain.into())
                    }
                } else {
                    unreachable!()
                }
            }
            Entry::Vacant(e) => {
                let created = event.interval.to_timestamp();
                let deliver_at = created + event.interval.as_secs();

                self.main.push(Schedule {
                    due: deliver_at.to_instant(),
                    inner: e.key().clone(),
                });
                let domain = e.key().domain_name().to_string();
                let path = core
                    .build_report_path(
                        ReportType::Tls(&domain),
                        policy_hash,
                        created,
                        event.interval,
                    )
                    .await;
                let v = e.insert(ReportType::Tls(ReportPath {
                    path: vec![ReportPolicy {
                        inner: path,
                        policy: policy_hash,
                    }],
                    size: 0,
                    created,
                    deliver_at: event.interval,
                }));
                (v.tls_path(), 0, domain.into())
            }
        };

        if let Some(domain) = create {
            let mut policy = PolicyDetails {
                policy_type: PolicyType::NoPolicyFound,
                policy_string: vec![],
                policy_domain: domain,
                mx_host: vec![],
            };

            match event.policy {
                super::PolicyType::Tlsa(tlsa) => {
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
                super::PolicyType::Sts(sts) => {
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
                records: vec![event.failure],
            };
            let bytes_written = json_write(&path.path[pos].inner, &entry).await;

            if bytes_written > 0 {
                path.size += bytes_written;
            } else {
                // Something went wrong, remove record
                if let Entry::Occupied(mut e) = self
                    .reports
                    .entry(ReportType::Tls(entry.policy.policy_domain))
                {
                    if let ReportType::Tls(path) = e.get_mut() {
                        path.path.retain(|p| p.policy != policy_hash);
                        if path.path.is_empty() {
                            e.remove_entry();
                        }
                    }
                }
            }
        } else if path.size < max_size {
            // Append to existing report
            path.size +=
                json_append(&path.path[pos].inner, &event.failure, max_size - path.size).await;
        }
    }
}

impl ReportPath<Vec<ReportPolicy<PathBuf>>> {
    fn cleanup_blocking(&self) {
        for path in &self.path {
            if let Err(err) = std::fs::remove_file(&path.inner) {
                tracing::error!(
                    context = "report",
                    report = "tls",
                    event = "error",
                    "Failed to delete file {}: {}",
                    path.inner.display(),
                    err
                );
            }
        }
    }
}
