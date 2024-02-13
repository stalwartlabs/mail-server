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

use std::collections::hash_map::Entry;

use ahash::AHashMap;
use mail_auth::{
    common::verify::VerifySignature,
    dmarc::{self, URI},
    report::{AuthFailureType, IdentityAlignment, PolicyPublished, Record, Report, SPFDomainScope},
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    SpfResult,
};
use store::{
    write::{now, BatchBuilder, Bincode, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, Serialize, ValueKey,
};
use tokio::io::{AsyncRead, AsyncWrite};
use utils::config::Rate;

use crate::{
    config::AggregateFrequency,
    core::{Session, SMTP},
    queue::{DomainPart, RecipientDomain},
};

use super::{scheduler::ToHash, DmarcEvent, ReportLock, SerializedSize};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DmarcFormat {
    pub rua: Vec<URI>,
    pub policy: PolicyPublished,
    pub records: Vec<Record>,
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dmarc_report(
        &self,
        message: &AuthenticatedMessage<'_>,
        auth_results: &AuthenticationResults<'_>,
        rejected: bool,
        dmarc_output: DmarcOutput,
        dkim_output: &[DkimOutput<'_>],
        arc_output: &Option<ArcOutput<'_>>,
    ) {
        let dmarc_record = dmarc_output.dmarc_record_cloned().unwrap();
        let config = &self.core.report.config.dmarc;

        // Send failure report
        if let (Some(failure_rate), Some(report_options)) = (
            self.core.eval_if::<Rate, _>(&config.send, self).await,
            dmarc_output.failure_report(),
        ) {
            // Verify that any external reporting addresses are authorized
            let rcpts = match self
                .core
                .resolvers
                .dns
                .verify_dmarc_report_address(dmarc_output.domain(), dmarc_record.ruf())
                .await
            {
                Some(rcpts) => {
                    if !rcpts.is_empty() {
                        let mut new_rcpts = Vec::with_capacity(rcpts.len());

                        for rcpt in rcpts {
                            if self.throttle_rcpt(rcpt.uri(), &failure_rate, "dmarc").await {
                                new_rcpts.push(rcpt.uri());
                            }
                        }

                        new_rcpts
                    } else {
                        if !dmarc_record.ruf().is_empty() {
                            tracing::debug!(
                                parent: &self.span,
                                context = "report",
                                report = "dkim",
                                event = "unauthorized-ruf",
                                ruf = ?dmarc_record.ruf(),
                                "Unauthorized external reporting addresses"
                            );
                        }
                        vec![]
                    }
                }
                None => {
                    tracing::debug!(
                        parent: &self.span,
                        context = "report",
                        report = "dmarc",
                        event = "dns-failure",
                        ruf = ?dmarc_record.ruf(),
                        "Failed to validate external report addresses",
                    );
                    vec![]
                }
            };

            // Throttle recipient
            if !rcpts.is_empty() {
                let mut report = Vec::with_capacity(128);
                let from_addr = self
                    .core
                    .eval_if(&config.address, self)
                    .await
                    .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
                let mut auth_failure = self
                    .new_auth_failure(AuthFailureType::Dmarc, rejected)
                    .with_authentication_results(auth_results.to_string())
                    .with_headers(message.raw_headers());

                // Report the first failed signature
                let dkim_failed = if let (
                    dmarc::Report::Dkim
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
                    Some(signature),
                ) = (
                    &report_options,
                    dkim_output.iter().find_map(|o| {
                        let s = o.signature()?;
                        if !matches!(o.result(), DkimResult::Pass) {
                            Some(s)
                        } else {
                            None
                        }
                    }),
                ) {
                    auth_failure = auth_failure
                        .with_dkim_domain(signature.domain())
                        .with_dkim_selector(signature.selector())
                        .with_dkim_identity(signature.identity());
                    true
                } else {
                    false
                };

                // Report SPF failure
                let spf_failed = if let (
                    dmarc::Report::Spf
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
                    Some(output),
                ) = (
                    &report_options,
                    self.data
                        .spf_ehlo
                        .as_ref()
                        .and_then(|s| {
                            if s.result() != SpfResult::Pass {
                                s.into()
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            self.data.spf_mail_from.as_ref().and_then(|s| {
                                if s.result() != SpfResult::Pass {
                                    s.into()
                                } else {
                                    None
                                }
                            })
                        }),
                ) {
                    auth_failure =
                        auth_failure.with_spf_dns(format!("txt : {} : v=SPF1", output.domain()));
                    // TODO use DNS record
                    true
                } else {
                    false
                };

                auth_failure
                    .with_identity_alignment(if dkim_failed && spf_failed {
                        IdentityAlignment::DkimSpf
                    } else if dkim_failed {
                        IdentityAlignment::Dkim
                    } else {
                        IdentityAlignment::Spf
                    })
                    .write_rfc5322(
                        (
                            self.core
                                .eval_if(&config.name, self)
                                .await
                                .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                                .as_str(),
                            from_addr.as_str(),
                        ),
                        &rcpts.join(", "),
                        &self
                            .core
                            .eval_if(&config.subject, self)
                            .await
                            .unwrap_or_else(|| "DMARC Report".to_string()),
                        &mut report,
                    )
                    .ok();

                tracing::info!(
                    parent: &self.span,
                    context = "report",
                    report = "dmarc",
                    event = "queue",
                    rcpt = ?rcpts,
                    "Queueing DMARC authentication failure report."
                );

                // Send report
                self.core
                    .send_report(
                        &from_addr,
                        rcpts.into_iter(),
                        report,
                        &config.sign,
                        &self.span,
                        true,
                    )
                    .await;
            } else {
                tracing::debug!(
                    parent: &self.span,
                    context = "report",
                    report = "dmarc",
                    event = "throttle",
                    ruf = ?dmarc_record.ruf(),
                );
            }
        }

        // Send agregate reports
        let interval = self
            .core
            .eval_if(&self.core.report.config.dmarc_aggregate.send, self)
            .await
            .unwrap_or(AggregateFrequency::Never);

        if matches!(interval, AggregateFrequency::Never) || dmarc_record.rua().is_empty() {
            return;
        }

        // Create DMARC report record
        let mut report_record = Record::new()
            .with_dmarc_output(&dmarc_output)
            .with_dkim_output(dkim_output)
            .with_source_ip(self.data.remote_ip)
            .with_header_from(message.from().domain_part())
            .with_envelope_from(
                self.data
                    .mail_from
                    .as_ref()
                    .map(|mf| mf.domain.as_str())
                    .unwrap_or_else(|| self.data.helo_domain.as_str()),
            );
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            report_record = report_record.with_spf_output(spf_ehlo, SPFDomainScope::Helo);
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            report_record = report_record.with_spf_output(spf_mail_from, SPFDomainScope::MailFrom);
        }
        if let Some(arc_output) = arc_output {
            report_record = report_record.with_arc_output(arc_output);
        }

        // Submit DMARC report event
        self.core
            .schedule_report(DmarcEvent {
                domain: dmarc_output.into_domain(),
                report_record,
                dmarc_record,
                interval,
            })
            .await;
    }
}

impl SMTP {
    pub async fn generate_dmarc_report(&self, event: ReportEvent) {
        let span = tracing::info_span!(
            "dmarc-report",
            domain = event.domain,
            range_from = event.seq_id,
            range_to = event.due,
        );

        // Deserialize report
        let dmarc = match self
            .shared
            .default_data_store
            .get_value::<Bincode<DmarcFormat>>(ValueKey::from(ValueClass::Queue(
                QueueClass::DmarcReportHeader(event.clone()),
            )))
            .await
        {
            Ok(Some(dmarc)) => dmarc.inner,
            Ok(None) => {
                tracing::warn!(
                    parent: &span,
                    event = "missing",
                    "Failed to read DMARC report: Report not found"
                );
                return;
            }
            Err(err) => {
                tracing::warn!(
                    parent: &span,
                    event = "error",
                    "Failed to read DMARC report: {}",
                    err
                );
                return;
            }
        };

        // Verify external reporting addresses
        let rua = match self
            .resolvers
            .dns
            .verify_dmarc_report_address(&event.domain, &dmarc.rua)
            .await
        {
            Some(rcpts) => {
                if !rcpts.is_empty() {
                    rcpts
                        .into_iter()
                        .map(|u| u.uri().to_string())
                        .collect::<Vec<_>>()
                } else {
                    tracing::info!(
                        parent: &span,
                        event = "failed",
                        reason = "unauthorized-rua",
                        rua = ?dmarc.rua,
                        "Unauthorized external reporting addresses"
                    );
                    self.delete_dmarc_report(event).await;
                    return;
                }
            }
            None => {
                tracing::info!(
                    parent: &span,
                    event = "failed",
                    reason = "dns-failure",
                    rua = ?dmarc.rua,
                    "Failed to validate external report addresses",
                );
                self.delete_dmarc_report(event).await;
                return;
            }
        };

        let mut serialized_size = serde_json::Serializer::new(SerializedSize::new(
            self.eval_if(
                &self.report.config.dmarc_aggregate.max_size,
                &RecipientDomain::new(event.domain.as_str()),
            )
            .await
            .unwrap_or(25 * 1024 * 1024),
        ));
        let _ = serde::Serialize::serialize(&dmarc, &mut serialized_size);
        let config = &self.report.config.dmarc_aggregate;

        // Group duplicates
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
            ReportEvent {
                due: event.due,
                policy_hash: event.policy_hash,
                seq_id: 0,
                domain: event.domain.clone(),
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
            ReportEvent {
                due: event.due,
                policy_hash: event.policy_hash,
                seq_id: u64::MAX,
                domain: event.domain.clone(),
            },
        )));
        let mut record_map = AHashMap::with_capacity(dmarc.records.len());
        if let Err(err) = self
            .shared
            .default_data_store
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |_, v| match record_map.entry(Bincode::<Record>::deserialize(v)?.inner) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += 1;
                        Ok(true)
                    }
                    Entry::Vacant(e) => {
                        if serde::Serialize::serialize(e.key(), &mut serialized_size).is_ok() {
                            e.insert(1u32);
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    }
                },
            )
            .await
        {
            tracing::warn!(
                parent: &span,
                event = "error",
                "Failed to read DMARC report: {}",
                err
            );
        }

        // Create report
        let mut report = Report::new()
            .with_policy_published(dmarc.policy)
            .with_date_range_begin(event.seq_id)
            .with_date_range_end(event.due)
            .with_report_id(format!("{}_{}", event.policy_hash, event.seq_id))
            .with_email(
                self.eval_if(
                    &config.address,
                    &RecipientDomain::new(event.domain.as_str()),
                )
                .await
                .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string()),
            );
        if let Some(org_name) = self
            .eval_if::<String, _>(
                &config.org_name,
                &RecipientDomain::new(event.domain.as_str()),
            )
            .await
        {
            report = report.with_org_name(org_name);
        }
        if let Some(contact_info) = self
            .eval_if::<String, _>(
                &config.contact_info,
                &RecipientDomain::new(event.domain.as_str()),
            )
            .await
        {
            report = report.with_extra_contact_info(contact_info);
        }
        for (record, count) in record_map {
            report.add_record(record.with_count(count));
        }
        let from_addr = self
            .eval_if(
                &config.address,
                &RecipientDomain::new(event.domain.as_str()),
            )
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let mut message = Vec::with_capacity(2048);
        let _ = report.write_rfc5322(
            &self
                .eval_if(
                    &self.report.config.submitter,
                    &RecipientDomain::new(event.domain.as_str()),
                )
                .await
                .unwrap_or_else(|| "localhost".to_string()),
            (
                self.eval_if(&config.name, &RecipientDomain::new(event.domain.as_str()))
                    .await
                    .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                    .as_str(),
                from_addr.as_str(),
            ),
            rua.iter().map(|a| a.as_str()),
            &mut message,
        );

        // Send report
        self.send_report(&from_addr, rua.iter(), message, &config.sign, &span, false)
            .await;

        self.delete_dmarc_report(event).await;
    }

    pub async fn delete_dmarc_report(&self, event: ReportEvent) {
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

        if let Err(err) = self
            .shared
            .default_data_store
            .delete_range(
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(from_key))),
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(to_key))),
            )
            .await
        {
            tracing::warn!(
                context = "report",
                event = "error",
                "Failed to remove repors: {}",
                err
            );
            return;
        }

        let mut batch = BatchBuilder::new();
        batch.clear(ValueClass::Queue(QueueClass::DmarcReportHeader(event)));
        if let Err(err) = self.shared.default_data_store.write(batch.build()).await {
            tracing::warn!(
                context = "report",
                event = "error",
                "Failed to remove repors: {}",
                err
            );
        }
    }

    pub async fn schedule_dmarc(&self, event: Box<DmarcEvent>) {
        let created = event.interval.to_timestamp();
        let deliver_at = created + event.interval.as_secs();
        let mut report_event = ReportEvent {
            due: deliver_at,
            policy_hash: event.dmarc_record.to_hash(),
            seq_id: created,
            domain: event.domain,
        };

        // Write policy if missing
        let mut builder = BatchBuilder::new();
        if self
            .shared
            .default_data_store
            .get_value::<()>(ValueKey::from(ValueClass::Queue(
                QueueClass::DmarcReportHeader(report_event.clone()),
            )))
            .await
            .unwrap_or_default()
            .is_none()
        {
            // Serialize report
            let entry = DmarcFormat {
                rua: event.dmarc_record.rua().to_vec(),
                policy: PolicyPublished::from_record(
                    report_event.domain.to_string(),
                    &event.dmarc_record,
                ),
                records: vec![],
            };

            // Write report
            builder.set(
                ValueClass::Queue(QueueClass::DmarcReportHeader(report_event.clone())),
                Bincode::new(entry).serialize(),
            );

            // Add lock
            builder.set(
                ValueClass::Queue(QueueClass::dmarc_lock(&report_event)),
                0u64.serialize(),
            );
        }

        // Write entry
        report_event.seq_id = self.queue.snowflake_id.generate().unwrap_or_else(now);
        builder.set(
            ValueClass::Queue(QueueClass::DmarcReportEvent(report_event)),
            Bincode::new(event.report_record).serialize(),
        );

        if let Err(err) = self.shared.default_data_store.write(builder.build()).await {
            tracing::error!(
                context = "report",
                event = "error",
                "Failed to write DMARC report event: {}",
                err
            );
        }
    }
}
