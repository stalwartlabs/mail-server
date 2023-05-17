/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, ResultType},
};
use mail_send::SmtpClient;
use smtp_proto::MAIL_REQUIRETLS;
use utils::config::ServerProtocol;

use crate::{
    config::{AggregateFrequency, TlsStrategy},
    core::SMTP,
    queue::ErrorDetails,
    reporting::{tls::TlsRptOptions, PolicyType, TlsEvent},
};

use super::{
    lookup::ToNextHop,
    mta_sts,
    session::{read_greeting, say_helo, try_start_tls, SessionParams, StartTlsResult},
    NextHop,
};
use crate::queue::{
    manager::Queue, throttle, DeliveryAttempt, Domain, Error, Event, OnHold, QueueEnvelope,
    Schedule, Status, WorkerResult,
};

impl DeliveryAttempt {
    pub async fn try_deliver(mut self, core: Arc<SMTP>, queue: &mut Queue) {
        // Check that the message still has recipients to be delivered
        let has_pending_delivery = self.has_pending_delivery();

        // Send any due Delivery Status Notifications
        core.queue.send_dsn(&mut self).await;

        if has_pending_delivery {
            // Re-queue the message if its not yet due for delivery
            let due = self.message.next_delivery_event();
            if due > Instant::now() {
                // Save changes to disk
                self.message.save_changes().await;

                queue.schedule(Schedule {
                    due,
                    inner: self.message,
                });
                return;
            }
        } else {
            // All message recipients expired, do not re-queue. (DSN has been already sent)
            self.message.remove().await;
            return;
        }

        // Throttle sender
        for throttle in &core.queue.config.throttle.sender {
            if let Err(err) = core
                .queue
                .is_allowed(
                    throttle,
                    self.message.as_ref(),
                    &mut self.in_flight,
                    &self.span,
                )
                .await
            {
                // Save changes to disk
                self.message.save_changes().await;

                match err {
                    throttle::Error::Concurrency { limiter } => {
                        queue.on_hold(OnHold {
                            next_due: self.message.next_event_after(Instant::now()),
                            limiters: vec![limiter],
                            message: self.message,
                        });
                    }
                    throttle::Error::Rate { retry_at } => {
                        queue.schedule(Schedule {
                            due: retry_at,
                            inner: self.message,
                        });
                    }
                }
                return;
            }
        }

        tokio::spawn(async move {
            let queue_config = &core.queue.config;
            let mut on_hold = Vec::new();
            let no_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

            let mut domains = std::mem::take(&mut self.message.domains);
            let mut recipients = std::mem::take(&mut self.message.recipients);
            'next_domain: for (domain_idx, domain) in domains.iter_mut().enumerate() {
                // Only process domains due for delivery
                if !matches!(&domain.status, Status::Scheduled | Status::TemporaryFailure(_)
                if domain.retry.due <= Instant::now())
                {
                    continue;
                }

                // Create new span for domain
                let span = tracing::info_span!(
                    parent: &self.span,
                    "attempt",
                    domain = domain.domain,
                    attempt_number = domain.retry.inner,
                );

                // Build envelope
                let mut envelope = QueueEnvelope {
                    message: self.message.as_ref(),
                    domain: &domain.domain,
                    mx: "",
                    remote_ip: no_ip,
                    local_ip: no_ip,
                };

                // Throttle recipient domain
                let mut in_flight = Vec::new();
                for throttle in &queue_config.throttle.rcpt {
                    if let Err(err) = core
                        .queue
                        .is_allowed(throttle, &envelope, &mut in_flight, &span)
                        .await
                    {
                        domain.set_throttle_error(err, &mut on_hold);
                        continue 'next_domain;
                    }
                }

                // Obtain next hop
                let (mut remote_hosts, is_smtp) = match queue_config.next_hop.eval(&envelope).await
                {
                    #[cfg(feature = "local_delivery")]
                    Some(next_hop) if next_hop.protocol == ServerProtocol::Jmap => {
                        // Deliver message locally
                        let delivery_result = self
                            .message
                            .deliver_local(
                                recipients.iter_mut().filter(|r| r.domain_idx == domain_idx),
                                &core.delivery_tx,
                                &span,
                            )
                            .await;

                        // Update status for the current domain and continue with the next one
                        domain
                            .set_status(delivery_result, queue_config.retry.eval(&envelope).await);
                        continue 'next_domain;
                    }
                    Some(next_hop) => (
                        vec![NextHop::Relay(next_hop)],
                        next_hop.protocol == ServerProtocol::Smtp,
                    ),
                    None => (Vec::with_capacity(0), true),
                };

                // Prepare TLS strategy
                let mut tls_strategy = TlsStrategy {
                    mta_sts: *queue_config.tls.mta_sts.eval(&envelope).await,
                    ..Default::default()
                };

                // Obtain TLS reporting
                let tls_report = match core.report.config.tls.send.eval(&envelope).await {
                    interval @ (AggregateFrequency::Hourly
                    | AggregateFrequency::Daily
                    | AggregateFrequency::Weekly)
                        if is_smtp =>
                    {
                        match core
                            .resolvers
                            .dns
                            .txt_lookup::<TlsRpt>(format!("_smtp._tls.{}.", envelope.domain))
                            .await
                        {
                            Ok(record) => {
                                tracing::debug!(parent: &span,
                            context = "tlsrpt",
                            event = "record-fetched",
                            record = ?record);

                                TlsRptOptions {
                                    record,
                                    interval: *interval,
                                }
                                .into()
                            }
                            Err(err) => {
                                tracing::debug!(
                                    parent: &span,
                                    context = "tlsrpt",
                                    "Failed to retrieve TLSRPT record: {}",
                                    err
                                );
                                None
                            }
                        }
                    }
                    _ => None,
                };

                // Obtain MTA-STS policy for domain
                let mta_sts_policy = if tls_strategy.try_mta_sts() && is_smtp {
                    match core
                        .lookup_mta_sts_policy(
                            envelope.domain,
                            *queue_config.timeout.mta_sts.eval(&envelope).await,
                        )
                        .await
                    {
                        Ok(mta_sts_policy) => {
                            tracing::debug!(
                                parent: &span,
                                context = "sts",
                                event = "policy-fetched",
                                policy = ?mta_sts_policy,
                            );

                            mta_sts_policy.into()
                        }
                        Err(err) => {
                            // Report MTA-STS error
                            if let Some(tls_report) = &tls_report {
                                match &err {
                                    mta_sts::Error::Dns(mail_auth::Error::DnsRecordNotFound(_)) => {
                                        if tls_strategy.is_mta_sts_required() {
                                            core.schedule_report(TlsEvent {
                                                policy: PolicyType::Sts(None),
                                                domain: envelope.domain.to_string(),
                                                failure: FailureDetails::new(ResultType::Other)
                                                .with_failure_reason_code("MTA-STS is required and no policy was found.")
                                                    .into(),
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                        }
                                    }
                                    mta_sts::Error::Dns(mail_auth::Error::DnsError(_)) => (),
                                    _ => {
                                        core.schedule_report(TlsEvent {
                                            policy: PolicyType::Sts(None),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(&err)
                                                .with_failure_reason_code(err.to_string())
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }
                                }
                            }

                            if tls_strategy.is_mta_sts_required() {
                                tracing::info!(
                                    parent: &span,
                                    context = "sts",
                                    event = "policy-fetch-failure",
                                    "Failed to retrieve MTA-STS policy: {}",
                                    err
                                );
                                domain.set_status(err, queue_config.retry.eval(&envelope).await);
                                continue 'next_domain;
                            } else {
                                tracing::debug!(
                                    parent: &span,
                                    context = "sts",
                                    event = "policy-fetch-failure",
                                    "Failed to retrieve MTA-STS policy: {}",
                                    err
                                );
                            }

                            None
                        }
                    }
                } else {
                    None
                };

                // Obtain remote hosts list
                let mx_list;
                if is_smtp {
                    // Lookup MX
                    mx_list = match core.resolvers.dns.mx_lookup(&domain.domain).await {
                        Ok(mx) => mx,
                        Err(err) => {
                            tracing::info!(
                                parent: &span,
                                context = "dns",
                                event = "mx-lookup-failed",
                                reason = %err,
                            );
                            domain.set_status(err, queue_config.retry.eval(&envelope).await);
                            continue 'next_domain;
                        }
                    };

                    if let Some(remote_hosts_) = mx_list
                        .to_remote_hosts(&domain.domain, *queue_config.max_mx.eval(&envelope).await)
                    {
                        remote_hosts = remote_hosts_;
                    } else {
                        tracing::info!(
                            parent: &span,
                            context = "dns",
                            event = "null-mx",
                            reason = "Domain does not accept messages (mull MX)",
                        );
                        domain.set_status(
                            Status::PermanentFailure(Error::DnsError(
                                "Domain does not accept messages (null MX)".to_string(),
                            )),
                            queue_config.retry.eval(&envelope).await,
                        );
                        continue 'next_domain;
                    }
                }

                // Try delivering message
                let max_multihomed = *queue_config.max_multihomed.eval(&envelope).await;
                let mut last_status = Status::Scheduled;
                'next_host: for remote_host in &remote_hosts {
                    // Validate MTA-STS
                    envelope.mx = remote_host.hostname();
                    if let Some(mta_sts_policy) = &mta_sts_policy {
                        if !mta_sts_policy.verify(envelope.mx) {
                            // Report MTA-STS failed verification
                            if let Some(tls_report) = &tls_report {
                                core.schedule_report(TlsEvent {
                                    policy: mta_sts_policy.into(),
                                    domain: envelope.domain.to_string(),
                                    failure: FailureDetails::new(ResultType::ValidationFailure)
                                        .with_receiving_mx_hostname(envelope.mx)
                                        .with_failure_reason_code("MX not authorized by policy.")
                                        .into(),
                                    tls_record: tls_report.record.clone(),
                                    interval: tls_report.interval,
                                })
                                .await;
                            }

                            tracing::warn!(
                                parent: &span,
                                context = "sts",
                                event = "policy-error",
                                mx = envelope.mx,
                                "MX not authorized by policy."
                            );

                            if mta_sts_policy.enforce() {
                                last_status = Status::PermanentFailure(Error::MtaStsError(
                                    format!("MX {:?} not authorized by policy.", envelope.mx),
                                ));
                                continue 'next_host;
                            }
                        }
                    }

                    // Obtain source and remote IPs
                    let (source_ip, remote_ips) = match core
                        .resolve_host(remote_host, &envelope, max_multihomed)
                        .await
                    {
                        Ok(result) => result,
                        Err(status) => {
                            tracing::info!(
                                parent: &span,
                                context = "dns",
                                event = "ip-lookup-failed",
                                mx = envelope.mx,
                                status = %status,
                            );

                            last_status = status;
                            continue 'next_host;
                        }
                    };

                    // Update TLS strategy
                    tls_strategy.dane = *queue_config.tls.dane.eval(&envelope).await;
                    tls_strategy.tls = *queue_config.tls.start.eval(&envelope).await;

                    // Lookup DANE policy
                    let dane_policy = if tls_strategy.try_dane() && is_smtp {
                        match core
                            .resolvers
                            .tlsa_lookup(format!("_25._tcp.{}.", envelope.mx))
                            .await
                        {
                            Ok(Some(tlsa)) => {
                                if tlsa.has_end_entities {
                                    tracing::debug!(
                                        parent: &span,
                                        context = "dane",
                                        event = "record-fetched",
                                        mx = envelope.mx,
                                        record = ?tlsa,
                                    );

                                    tlsa.into()
                                } else {
                                    tracing::info!(
                                        parent: &span,
                                        context = "dane",
                                        event = "no-tlsa-records",
                                        mx = envelope.mx,
                                        "No valid TLSA records were found.",
                                    );

                                    // Report invalid TLSA record
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: tlsa.into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(ResultType::TlsaInvalid)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code("Invalid TLSA record.")
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    if tls_strategy.is_dane_required() {
                                        last_status = Status::PermanentFailure(Error::DaneError(
                                            ErrorDetails {
                                                entity: envelope.mx.to_string(),
                                                details: "No valid TLSA records were found"
                                                    .to_string(),
                                            },
                                        ));
                                        continue 'next_host;
                                    }
                                    None
                                }
                            }
                            Ok(None) => {
                                if tls_strategy.is_dane_required() {
                                    // Report DANE required
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: PolicyType::Tlsa(None),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(ResultType::DaneRequired)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code(
                                                    "No TLSA DNSSEC records found.",
                                                )
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    tracing::info!(
                                        parent: &span,
                                        context = "dane",
                                        event = "tlsa-dnssec-missing",
                                        mx = envelope.mx,
                                        "No TLSA DNSSEC records found."
                                    );

                                    last_status =
                                        Status::PermanentFailure(Error::DaneError(ErrorDetails {
                                            entity: envelope.mx.to_string(),
                                            details: "No TLSA DNSSEC records found".to_string(),
                                        }));
                                    continue 'next_host;
                                }
                                None
                            }
                            Err(err) => {
                                if tls_strategy.is_dane_required() {
                                    tracing::info!(
                                        parent: &span,
                                        context = "dane",
                                        event = "tlsa-missing",
                                        mx = envelope.mx,
                                        "No TLSA records found."
                                    );

                                    last_status =
                                        if matches!(&err, mail_auth::Error::DnsRecordNotFound(_)) {
                                            // Report DANE required
                                            if let Some(tls_report) = &tls_report {
                                                core.schedule_report(TlsEvent {
                                                    policy: PolicyType::Tlsa(None),
                                                    domain: envelope.domain.to_string(),
                                                    failure: FailureDetails::new(
                                                        ResultType::DaneRequired,
                                                    )
                                                    .with_receiving_mx_hostname(envelope.mx)
                                                    .with_failure_reason_code(
                                                        "No TLSA records found for MX.",
                                                    )
                                                    .into(),
                                                    tls_record: tls_report.record.clone(),
                                                    interval: tls_report.interval,
                                                })
                                                .await;
                                            }

                                            Status::PermanentFailure(Error::DaneError(
                                                ErrorDetails {
                                                    entity: envelope.mx.to_string(),
                                                    details: "No TLSA records found".to_string(),
                                                },
                                            ))
                                        } else {
                                            err.into()
                                        };
                                    continue 'next_host;
                                }
                                None
                            }
                        }
                    } else {
                        None
                    };

                    // Try each IP address
                    envelope.local_ip = source_ip.unwrap_or(no_ip);
                    'next_ip: for remote_ip in remote_ips {
                        // Throttle remote host
                        let mut in_flight_host = Vec::new();
                        envelope.remote_ip = remote_ip;
                        for throttle in &queue_config.throttle.host {
                            if let Err(err) = core
                                .queue
                                .is_allowed(throttle, &envelope, &mut in_flight_host, &span)
                                .await
                            {
                                domain.set_throttle_error(err, &mut on_hold);
                                continue 'next_domain;
                            }
                        }

                        // Connect
                        let mut smtp_client = match if let Some(ip_addr) = source_ip {
                            SmtpClient::connect_using(
                                ip_addr,
                                SocketAddr::new(remote_ip, remote_host.port()),
                                *queue_config.timeout.connect.eval(&envelope).await,
                            )
                            .await
                        } else {
                            SmtpClient::connect(
                                SocketAddr::new(remote_ip, remote_host.port()),
                                *queue_config.timeout.connect.eval(&envelope).await,
                            )
                            .await
                        } {
                            Ok(smtp_client) => {
                                tracing::debug!(
                                    parent: &span,
                                    context = "connect",
                                    event = "success",
                                    mx = envelope.mx,
                                    source_ip = %source_ip.unwrap_or(no_ip),
                                    remote_ip = %remote_ip,
                                    remote_port = remote_host.port(),
                                );

                                smtp_client
                            }
                            Err(err) => {
                                tracing::info!(
                                    parent: &span,
                                    context = "connect",
                                    event = "failed",
                                    mx = envelope.mx,
                                    reason = %err,
                                );
                                last_status = Status::from_smtp_error(envelope.mx, "", err);
                                continue 'next_ip;
                            }
                        };

                        // Obtail session parameters
                        let params = SessionParams {
                            span: &span,
                            credentials: remote_host.credentials(),
                            is_smtp: remote_host.is_smtp(),
                            hostname: envelope.mx,
                            local_hostname: queue_config.hostname.eval(&envelope).await,
                            timeout_ehlo: *queue_config.timeout.ehlo.eval(&envelope).await,
                            timeout_mail: *queue_config.timeout.mail.eval(&envelope).await,
                            timeout_rcpt: *queue_config.timeout.rcpt.eval(&envelope).await,
                            timeout_data: *queue_config.timeout.data.eval(&envelope).await,
                        };

                        // Prepare TLS connector
                        let tls_connector = if !remote_host.allow_invalid_certs() {
                            &core.queue.connectors.pki_verify
                        } else {
                            &core.queue.connectors.dummy_verify
                        };

                        let delivery_result = if !remote_host.implicit_tls() {
                            // Read greeting
                            smtp_client.timeout =
                                *queue_config.timeout.greeting.eval(&envelope).await;
                            if let Err(status) = read_greeting(&mut smtp_client, envelope.mx).await
                            {
                                tracing::info!(
                                    parent: &span,
                                    context = "greeting",
                                    event = "invalid",
                                    mx = envelope.mx,
                                    status = %status,
                                );

                                last_status = status;
                                continue 'next_host;
                            }

                            // Say EHLO
                            let capabilties = match say_helo(&mut smtp_client, &params).await {
                                Ok(capabilities) => capabilities,
                                Err(status) => {
                                    tracing::info!(
                                        parent: &span,
                                        context = "ehlo",
                                        event = "rejected",
                                        mx = envelope.mx,
                                        status = %status,
                                    );

                                    last_status = status;
                                    continue 'next_host;
                                }
                            };

                            // Try starting TLS
                            smtp_client.timeout = *queue_config.timeout.tls.eval(&envelope).await;
                            match try_start_tls(
                                smtp_client,
                                tls_connector,
                                envelope.mx,
                                &capabilties,
                            )
                            .await
                            {
                                StartTlsResult::Success { smtp_client } => {
                                    // Verify DANE
                                    if let Some(dane_policy) = &dane_policy {
                                        if let Err(status) = dane_policy.verify(
                                            &span,
                                            envelope.mx,
                                            smtp_client.tls_connection().peer_certificates(),
                                        ) {
                                            // Report DANE verification failure
                                            if let Some(tls_report) = &tls_report {
                                                core.schedule_report(TlsEvent {
                                                    policy: dane_policy.into(),
                                                    domain: envelope.domain.to_string(),
                                                    failure: FailureDetails::new(
                                                        ResultType::ValidationFailure,
                                                    )
                                                    .with_receiving_mx_hostname(envelope.mx)
                                                    .with_receiving_ip(remote_ip)
                                                    .with_failure_reason_code(
                                                        "No matching certificates found.",
                                                    )
                                                    .into(),
                                                    tls_record: tls_report.record.clone(),
                                                    interval: tls_report.interval,
                                                })
                                                .await;
                                            }

                                            last_status = status;
                                            continue 'next_host;
                                        }
                                    }

                                    // Report TLS success
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: None,
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    // Deliver message over TLS
                                    self.message
                                        .deliver(
                                            smtp_client,
                                            recipients
                                                .iter_mut()
                                                .filter(|r| r.domain_idx == domain_idx),
                                            params,
                                        )
                                        .await
                                }
                                StartTlsResult::Unavailable {
                                    response,
                                    smtp_client,
                                } => {
                                    // Report unavailable STARTTLS
                                    let reason =
                                        response.as_ref().map(|r| r.to_string()).unwrap_or_else(
                                            || "STARTTLS was not advertised by host".to_string(),
                                        );

                                    tracing::info!(
                                        parent: &span,
                                        context = "tls",
                                        event = "unavailable",
                                        mx = envelope.mx,
                                        reason = reason,
                                    );

                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(
                                                ResultType::StartTlsNotSupported,
                                            )
                                            .with_receiving_mx_hostname(envelope.mx)
                                            .with_receiving_ip(remote_ip)
                                            .with_failure_reason_code(reason)
                                            .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    if tls_strategy.is_tls_required()
                                        || (self.message.flags & MAIL_REQUIRETLS) != 0
                                        || mta_sts_policy.is_some()
                                        || dane_policy.is_some()
                                    {
                                        last_status =
                                            Status::from_starttls_error(envelope.mx, response);
                                        continue 'next_host;
                                    } else {
                                        // TLS is not required, proceed in plain-text
                                        self.message
                                            .deliver(
                                                smtp_client,
                                                recipients
                                                    .iter_mut()
                                                    .filter(|r| r.domain_idx == domain_idx),
                                                params,
                                            )
                                            .await
                                    }
                                }
                                StartTlsResult::Error { error } => {
                                    tracing::info!(
                                        parent: &span,
                                        context = "tls",
                                        event = "failed",
                                        mx = envelope.mx,
                                        error = %error,
                                    );

                                    // Report TLS failure
                                    if let (Some(tls_report), mail_send::Error::Tls(error)) =
                                        (&tls_report, &error)
                                    {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(
                                                ResultType::CertificateNotTrusted,
                                            )
                                            .with_receiving_mx_hostname(envelope.mx)
                                            .with_receiving_ip(remote_ip)
                                            .with_failure_reason_code(error.to_string())
                                            .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }
                                    last_status = Status::from_tls_error(envelope.mx, error);
                                    continue 'next_host;
                                }
                            }
                        } else {
                            // Start TLS
                            smtp_client.timeout = *queue_config.timeout.tls.eval(&envelope).await;
                            let mut smtp_client =
                                match smtp_client.into_tls(tls_connector, envelope.mx).await {
                                    Ok(smtp_client) => smtp_client,
                                    Err(error) => {
                                        tracing::info!(
                                            parent: &span,
                                            context = "tls",
                                            event = "failed",
                                            mx = envelope.mx,
                                            error = %error,
                                        );

                                        last_status = Status::from_tls_error(envelope.mx, error);
                                        continue 'next_host;
                                    }
                                };

                            // Read greeting
                            smtp_client.timeout =
                                *queue_config.timeout.greeting.eval(&envelope).await;
                            if let Err(status) = read_greeting(&mut smtp_client, envelope.mx).await
                            {
                                tracing::info!(
                                    parent: &span,
                                    context = "greeting",
                                    event = "invalid",
                                    mx = envelope.mx,
                                    status = %status,
                                );

                                last_status = status;
                                continue 'next_host;
                            }

                            // Deliver message
                            self.message
                                .deliver(
                                    smtp_client,
                                    recipients.iter_mut().filter(|r| r.domain_idx == domain_idx),
                                    params,
                                )
                                .await
                        };

                        // Update status for the current domain and continue with the next one
                        domain
                            .set_status(delivery_result, queue_config.retry.eval(&envelope).await);
                        continue 'next_domain;
                    }
                }

                // Update status
                domain.set_status(last_status, queue_config.retry.eval(&envelope).await);
            }
            self.message.domains = domains;
            self.message.recipients = recipients;

            // Send Delivery Status Notifications
            core.queue.send_dsn(&mut self).await;

            // Notify queue manager
            let span = self.span;
            let result = if !on_hold.is_empty() {
                // Release quota for completed deliveries
                self.message.release_quota();

                // Save changes to disk
                self.message.save_changes().await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "requeue",
                    reason = "concurrency-limited",
                    "Too many outbound concurrent connections, message moved to on-hold queue."
                );

                WorkerResult::OnHold(OnHold {
                    next_due: self.message.next_event_after(Instant::now()),
                    limiters: on_hold,
                    message: self.message,
                })
            } else if let Some(due) = self.message.next_event() {
                // Release quota for completed deliveries
                self.message.release_quota();

                // Save changes to disk
                self.message.save_changes().await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "requeue",
                    reason = "delivery-incomplete",
                    "Delivery was not possible, message re-queued for delivery."
                );

                WorkerResult::Retry(Schedule {
                    due,
                    inner: self.message,
                })
            } else {
                // Delete message from queue
                self.message.remove().await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "completed",
                    "Delivery completed."
                );

                WorkerResult::Done
            };
            if core.queue.tx.send(Event::Done(result)).await.is_err() {
                tracing::warn!(
                    parent: &span,
                    "Channel closed while trying to notify queue manager."
                );
            }
        });
    }

    /// Marks as failed all domains that reached their expiration time
    pub fn has_pending_delivery(&mut self) -> bool {
        let now = Instant::now();
        let mut has_pending_delivery = false;
        let span = self.span.clone();

        for (idx, domain) in self.message.domains.iter_mut().enumerate() {
            match &domain.status {
                Status::TemporaryFailure(err) if domain.expires <= now => {
                    tracing::info!(
                        parent: &span,
                        event = "delivery-expired",
                        domain = domain.domain,
                        reason = %err,
                    );

                    for rcpt in &mut self.message.recipients {
                        if rcpt.domain_idx == idx {
                            rcpt.status = std::mem::replace(&mut rcpt.status, Status::Scheduled)
                                .into_permanent();
                        }
                    }

                    domain.status =
                        std::mem::replace(&mut domain.status, Status::Scheduled).into_permanent();
                    domain.changed = true;
                }
                Status::Scheduled if domain.expires <= now => {
                    tracing::info!(
                        parent: &span,
                        event = "delivery-expired",
                        domain = domain.domain,
                        reason = "Queue rate limit exceeded.",
                    );

                    for rcpt in &mut self.message.recipients {
                        if rcpt.domain_idx == idx {
                            rcpt.status = std::mem::replace(&mut rcpt.status, Status::Scheduled)
                                .into_permanent();
                        }
                    }

                    domain.status = Status::PermanentFailure(Error::Io(
                        "Queue rate limit exceeded.".to_string(),
                    ));
                    domain.changed = true;
                }
                Status::Completed(_) | Status::PermanentFailure(_) => (),
                _ => {
                    has_pending_delivery = true;
                }
            }
        }

        has_pending_delivery
    }
}

impl Domain {
    pub fn set_status(&mut self, status: impl Into<Status<(), Error>>, schedule: &[Duration]) {
        self.status = status.into();
        self.changed = true;
        if matches!(
            &self.status,
            Status::TemporaryFailure(_) | Status::Scheduled
        ) {
            self.retry(schedule);
        }
    }

    pub fn retry(&mut self, schedule: &[Duration]) {
        self.retry.due =
            Instant::now() + schedule[std::cmp::min(self.retry.inner as usize, schedule.len() - 1)];
        self.retry.inner += 1;
    }
}
