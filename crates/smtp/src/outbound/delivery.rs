/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::outbound::dane::verify::TlsaVerify;
use crate::outbound::mta_sts::verify::VerifyPolicy;
use common::config::{
    server::ServerProtocol,
    smtp::{queue::RequireOptional, report::AggregateFrequency},
};
use mail_auth::{
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, ResultType},
};
use mail_send::SmtpClient;
use smtp_proto::MAIL_REQUIRETLS;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use store::write::{now, BatchBuilder, QueueClass, QueueEvent, ValueClass};

use crate::{
    core::SMTP,
    queue::{ErrorDetails, Message},
    reporting::{tls::TlsRptOptions, PolicyType, TlsEvent},
};

use super::{
    lookup::ToNextHop,
    mta_sts,
    session::{read_greeting, say_helo, try_start_tls, SessionParams, StartTlsResult},
    NextHop, TlsStrategy,
};
use crate::queue::{
    throttle, DeliveryAttempt, Domain, Error, Event, OnHold, QueueEnvelope, Status,
};

impl DeliveryAttempt {
    pub async fn try_deliver(mut self, core: SMTP) {
        tokio::spawn(async move {
            // Lock message
            self.event = if let Some(event) = core.try_lock_event(self.event).await {
                event
            } else {
                return;
            };

            // Fetch message
            let mut message = if let Some(message) = core.read_message(self.event.queue_id).await {
                message
            } else {
                // Message no longer exists, delete queue event.
                let mut batch = BatchBuilder::new();
                batch.clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: self.event.due,
                    queue_id: self.event.queue_id,
                })));
                let _ = core.core.storage.data.write(batch.build()).await;
                return;
            };

            let span = tracing::info_span!(
                "delivery",
                "id" = message.id,
                "return_path" = if !message.return_path.is_empty() {
                    message.return_path.as_ref()
                } else {
                    "<>"
                },
                "nrcpt" = message.recipients.len(),
                "size" = message.size
            );

            // Check that the message still has recipients to be delivered
            let has_pending_delivery = message.has_pending_delivery(&span);

            // Send any due Delivery Status Notifications
            core.send_dsn(&mut message, &span).await;

            if has_pending_delivery {
                // Re-queue the message if its not yet due for delivery
                let due = message.next_delivery_event();
                if due > now() {
                    // Save changes
                    message
                        .save_changes(&core, self.event.due.into(), due.into())
                        .await;
                    if core.inner.queue_tx.send(Event::Reload).await.is_err() {
                        tracing::warn!("Channel closed while trying to notify queue manager.");
                    }
                    return;
                }
            } else {
                // All message recipients expired, do not re-queue. (DSN has been already sent)
                message.remove(&core, self.event.due).await;
                if core.inner.queue_tx.send(Event::Reload).await.is_err() {
                    tracing::warn!("Channel closed while trying to notify queue manager.");
                }

                return;
            }

            // Throttle sender
            for throttle in &core.core.smtp.queue.throttle.sender {
                if let Err(err) = core
                    .is_allowed(throttle, &message, &mut self.in_flight, &span)
                    .await
                {
                    let event = match err {
                        throttle::Error::Concurrency { limiter } => {
                            // Save changes to disk
                            let next_due = message.next_event_after(now());
                            message.save_changes(&core, None, None).await;

                            Event::OnHold(OnHold {
                                next_due,
                                limiters: vec![limiter],
                                message: self.event,
                            })
                        }
                        throttle::Error::Rate { retry_at } => {
                            // Save changes to disk
                            let next_event = std::cmp::min(
                                retry_at,
                                message.next_event_after(now()).unwrap_or(u64::MAX),
                            );
                            message
                                .save_changes(&core, self.event.due.into(), next_event.into())
                                .await;

                            Event::Reload
                        }
                    };

                    if core.inner.queue_tx.send(event).await.is_err() {
                        tracing::warn!("Channel closed while trying to notify queue manager.");
                    }
                    return;
                }
            }

            let queue_config = &core.core.smtp.queue;
            let mut on_hold = Vec::new();
            let no_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            let mut recipients = std::mem::take(&mut message.recipients);
            'next_domain: for domain_idx in 0..message.domains.len() {
                // Only process domains due for delivery
                let domain = &message.domains[domain_idx];
                if !matches!(&domain.status, Status::Scheduled | Status::TemporaryFailure(_)
                if domain.retry.due <= now())
                {
                    continue;
                }

                // Create new span for domain
                let span = tracing::info_span!(
                    parent: &span,
                    "attempt",
                    domain = domain.domain,
                    attempt_number = domain.retry.inner,
                );

                // Build envelope
                let mut envelope = QueueEnvelope::new(&message, domain_idx);

                // Throttle recipient domain
                let mut in_flight = Vec::new();
                for throttle in &queue_config.throttle.rcpt {
                    if let Err(err) = core
                        .is_allowed(throttle, &envelope, &mut in_flight, &span)
                        .await
                    {
                        message.domains[domain_idx].set_throttle_error(err, &mut on_hold);
                        continue 'next_domain;
                    }
                }

                // Obtain next hop
                let (mut remote_hosts, is_smtp) = match core
                    .core
                    .eval_if::<String, _>(&queue_config.next_hop, &envelope)
                    .await
                    .and_then(|name| core.core.get_relay_host(&name))
                {
                    Some(next_hop) if next_hop.protocol == ServerProtocol::Http => {
                        // Deliver message locally
                        let delivery_result = message
                            .deliver_local(
                                recipients.iter_mut().filter(|r| r.domain_idx == domain_idx),
                                &core.inner.ipc.delivery_tx,
                                &span,
                            )
                            .await;

                        // Update status for the current domain and continue with the next one
                        let schedule = core
                            .core
                            .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                            .await
                            .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                        message.domains[domain_idx].set_status(delivery_result, &schedule);
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
                    mta_sts: core
                        .core
                        .eval_if(&queue_config.tls.mta_sts, &envelope)
                        .await
                        .unwrap_or(RequireOptional::Optional),
                    ..Default::default()
                };
                let allow_invalid_certs = core
                    .core
                    .eval_if(&queue_config.tls.invalid_certs, &envelope)
                    .await
                    .unwrap_or(false);

                // Obtain TLS reporting
                let tls_report = match core
                    .core
                    .eval_if(&core.core.smtp.report.tls.send, &envelope)
                    .await
                    .unwrap_or(AggregateFrequency::Never)
                {
                    interval @ (AggregateFrequency::Hourly
                    | AggregateFrequency::Daily
                    | AggregateFrequency::Weekly)
                        if is_smtp =>
                    {
                        match core
                            .core
                            .smtp
                            .resolvers
                            .dns
                            .txt_lookup::<TlsRpt>(format!("_smtp._tls.{}.", domain.domain))
                            .await
                        {
                            Ok(record) => {
                                tracing::debug!(parent: &span,
                            context = "tlsrpt",
                            event = "record-fetched",
                            record = ?record);

                                TlsRptOptions { record, interval }.into()
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
                            &domain.domain,
                            core.core
                                .eval_if(&queue_config.timeout.mta_sts, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(10 * 60)),
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
                                                domain: domain.domain.to_string(),
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
                                            domain: domain.domain.to_string(),
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
                                let schedule = core
                                    .core
                                    .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                                    .await
                                    .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                                message.domains[domain_idx].set_status(err, &schedule);
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
                if is_smtp && remote_hosts.is_empty() {
                    // Lookup MX
                    mx_list = match core.core.smtp.resolvers.dns.mx_lookup(&domain.domain).await {
                        Ok(mx) => mx,
                        Err(err) => {
                            tracing::info!(
                                parent: &span,
                                context = "dns",
                                event = "mx-lookup-failed",
                                reason = %err,
                            );
                            let schedule = core
                                .core
                                .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                                .await
                                .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                            message.domains[domain_idx].set_status(err, &schedule);
                            continue 'next_domain;
                        }
                    };

                    if let Some(remote_hosts_) = mx_list.to_remote_hosts(
                        &domain.domain,
                        core.core
                            .eval_if(&queue_config.max_mx, &envelope)
                            .await
                            .unwrap_or(5),
                    ) {
                        remote_hosts = remote_hosts_;
                    } else {
                        tracing::info!(
                            parent: &span,
                            context = "dns",
                            event = "null-mx",
                            reason = "Domain does not accept messages (mull MX)",
                        );
                        let schedule = core
                            .core
                            .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                            .await
                            .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                        message.domains[domain_idx].set_status(
                            Status::PermanentFailure(Error::DnsError(
                                "Domain does not accept messages (null MX)".to_string(),
                            )),
                            &schedule,
                        );
                        continue 'next_domain;
                    }
                }

                // Try delivering message
                let max_multihomed = core
                    .core
                    .eval_if(&queue_config.max_multihomed, &envelope)
                    .await
                    .unwrap_or(2);
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
                                    domain: domain.domain.to_string(),
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
                    let resolve_result = match core
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
                    tls_strategy.dane = core
                        .core
                        .eval_if(&queue_config.tls.dane, &envelope)
                        .await
                        .unwrap_or(RequireOptional::Optional);
                    tls_strategy.tls = core
                        .core
                        .eval_if(&queue_config.tls.start, &envelope)
                        .await
                        .unwrap_or(RequireOptional::Optional);

                    // Lookup DANE policy
                    let dane_policy = if tls_strategy.try_dane() && is_smtp {
                        match core.tlsa_lookup(format!("_25._tcp.{}.", envelope.mx)).await {
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
                                            domain: domain.domain.to_string(),
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
                                            domain: domain.domain.to_string(),
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
                                                    domain: domain.domain.to_string(),
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
                    'next_ip: for remote_ip in resolve_result.remote_ips {
                        // Set source IP, if any
                        let source_ip = if remote_ip.is_ipv4() {
                            resolve_result.source_ipv4
                        } else {
                            resolve_result.source_ipv6
                        };
                        envelope.local_ip = source_ip.unwrap_or(no_ip);

                        // Throttle remote host
                        let mut in_flight_host = Vec::new();
                        envelope.remote_ip = remote_ip;
                        for throttle in &queue_config.throttle.host {
                            if let Err(err) = core
                                .is_allowed(throttle, &envelope, &mut in_flight_host, &span)
                                .await
                            {
                                message.domains[domain_idx].set_throttle_error(err, &mut on_hold);
                                continue 'next_domain;
                            }
                        }

                        // Connect
                        let conn_timeout = core
                            .core
                            .eval_if(&queue_config.timeout.connect, &envelope)
                            .await
                            .unwrap_or_else(|| Duration::from_secs(5 * 60));
                        let mut smtp_client = match if let Some(ip_addr) = source_ip {
                            SmtpClient::connect_using(
                                ip_addr,
                                SocketAddr::new(remote_ip, remote_host.port()),
                                conn_timeout,
                            )
                            .await
                        } else {
                            SmtpClient::connect(
                                SocketAddr::new(remote_ip, remote_host.port()),
                                conn_timeout,
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

                        // Obtain session parameters
                        let local_hostname = core
                            .core
                            .eval_if::<String, _>(&queue_config.hostname, &envelope)
                            .await
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| {
                                tracing::warn!(parent: &span,
                                    context = "queue",
                                    event = "ehlo",
                                    "No outbound hostname configured, using 'local.host'."
                                );
                                "local.host".to_string()
                            });
                        let params = SessionParams {
                            span: &span,
                            core: &core,
                            credentials: remote_host.credentials(),
                            is_smtp: remote_host.is_smtp(),
                            hostname: envelope.mx,
                            local_hostname: &local_hostname,
                            timeout_ehlo: core
                                .core
                                .eval_if(&queue_config.timeout.ehlo, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60)),
                            timeout_mail: core
                                .core
                                .eval_if(&queue_config.timeout.mail, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60)),
                            timeout_rcpt: core
                                .core
                                .eval_if(&queue_config.timeout.rcpt, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60)),
                            timeout_data: core
                                .core
                                .eval_if(&queue_config.timeout.data, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60)),
                        };

                        // Prepare TLS connector
                        let is_strict_tls = tls_strategy.is_tls_required()
                            || (message.flags & MAIL_REQUIRETLS) != 0
                            || mta_sts_policy.is_some()
                            || dane_policy.is_some();
                        let tls_connector =
                            if allow_invalid_certs || remote_host.allow_invalid_certs() {
                                &core.inner.connectors.dummy_verify
                            } else {
                                &core.inner.connectors.pki_verify
                            };

                        let delivery_result = if !remote_host.implicit_tls() {
                            // Read greeting
                            smtp_client.timeout = core
                                .core
                                .eval_if(&queue_config.timeout.greeting, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60));
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
                            if tls_strategy.try_start_tls() {
                                smtp_client.timeout = core
                                    .core
                                    .eval_if(&queue_config.timeout.tls, &envelope)
                                    .await
                                    .unwrap_or_else(|| Duration::from_secs(3 * 60));
                                match try_start_tls(
                                    smtp_client,
                                    tls_connector,
                                    envelope.mx,
                                    &capabilties,
                                )
                                .await
                                {
                                    StartTlsResult::Success { smtp_client } => {
                                        tracing::debug!(
                                            parent: &span,
                                            context = "tls",
                                            event = "success",
                                            mx = envelope.mx,
                                            protocol = ?smtp_client.tls_connection().protocol_version(),
                                            cipher = ?smtp_client.tls_connection().negotiated_cipher_suite(),
                                        );

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
                                                        domain: domain.domain.to_string(),
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
                                                domain: domain.domain.to_string(),
                                                failure: None,
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                        }

                                        // Deliver message over TLS
                                        message
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
                                        let reason = response
                                            .as_ref()
                                            .map(|r| r.to_string())
                                            .unwrap_or_else(|| {
                                                "STARTTLS was not advertised by host".to_string()
                                            });

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
                                                domain: domain.domain.to_string(),
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

                                        if is_strict_tls {
                                            last_status =
                                                Status::from_starttls_error(envelope.mx, response);
                                            continue 'next_host;
                                        } else {
                                            // TLS is not required, proceed in plain-text
                                            message
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
                                                domain: domain.domain.to_string(),
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

                                        last_status = if is_strict_tls {
                                            Status::from_tls_error(envelope.mx, error)
                                        } else {
                                            Status::from_tls_error(envelope.mx, error)
                                                .into_temporary()
                                        };
                                        continue 'next_host;
                                    }
                                }
                            } else {
                                // TLS has been disabled
                                tracing::info!(
                                    parent: &span,
                                    context = "tls",
                                    event = "disabled",
                                    mx = envelope.mx,
                                    reason = "TLS is disabled for this host.",
                                );

                                message
                                    .deliver(
                                        smtp_client,
                                        recipients
                                            .iter_mut()
                                            .filter(|r| r.domain_idx == domain_idx),
                                        params,
                                    )
                                    .await
                            }
                        } else {
                            // Start TLS
                            smtp_client.timeout = core
                                .core
                                .eval_if(&queue_config.timeout.tls, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(3 * 60));
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
                            smtp_client.timeout = core
                                .core
                                .eval_if(&queue_config.timeout.greeting, &envelope)
                                .await
                                .unwrap_or_else(|| Duration::from_secs(5 * 60));
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
                            message
                                .deliver(
                                    smtp_client,
                                    recipients.iter_mut().filter(|r| r.domain_idx == domain_idx),
                                    params,
                                )
                                .await
                        };

                        // Update status for the current domain and continue with the next one
                        let schedule = core
                            .core
                            .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                            .await
                            .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                        message.domains[domain_idx].set_status(delivery_result, &schedule);
                        continue 'next_domain;
                    }
                }

                // Update status
                let schedule = core
                    .core
                    .eval_if::<Vec<Duration>, _>(&queue_config.retry, &envelope)
                    .await
                    .unwrap_or_else(|| vec![Duration::from_secs(60)]);
                message.domains[domain_idx].set_status(last_status, &schedule);
            }
            message.recipients = recipients;

            // Send Delivery Status Notifications
            core.send_dsn(&mut message, &span).await;

            // Notify queue manager
            let span = span;
            let result = if !on_hold.is_empty() {
                // Save changes to disk
                let next_due = message.next_event_after(now());
                message.save_changes(&core, None, None).await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "requeue",
                    reason = "concurrency-limited",
                    "Too many outbound concurrent connections, message moved to on-hold queue."
                );

                Event::OnHold(OnHold {
                    next_due,
                    limiters: on_hold,
                    message: self.event,
                })
            } else if let Some(due) = message.next_event() {
                // Save changes to disk
                message
                    .save_changes(&core, self.event.due.into(), due.into())
                    .await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "requeue",
                    reason = "delivery-incomplete",
                    "Delivery was not possible, message re-queued for delivery."
                );

                Event::Reload
            } else {
                // Delete message from queue
                message.remove(&core, self.event.due).await;

                tracing::info!(
                    parent: &span,
                    context = "queue",
                    event = "completed",
                    "Delivery completed."
                );

                Event::Reload
            };
            if core.inner.queue_tx.send(result).await.is_err() {
                tracing::warn!(
                    parent: &span,
                    "Channel closed while trying to notify queue manager."
                );
            }
        });
    }
}

impl Message {
    /// Marks as failed all domains that reached their expiration time
    pub fn has_pending_delivery(&mut self, span: &tracing::Span) -> bool {
        let now = now();
        let mut has_pending_delivery = false;

        for (idx, domain) in self.domains.iter_mut().enumerate() {
            match &domain.status {
                Status::TemporaryFailure(err) if domain.expires <= now => {
                    tracing::info!(
                        parent: span,
                        event = "delivery-expired",
                        domain = domain.domain,
                        reason = %err,
                    );

                    for rcpt in &mut self.recipients {
                        if rcpt.domain_idx == idx {
                            rcpt.status = std::mem::replace(&mut rcpt.status, Status::Scheduled)
                                .into_permanent();
                        }
                    }

                    domain.status =
                        std::mem::replace(&mut domain.status, Status::Scheduled).into_permanent();
                }
                Status::Scheduled if domain.expires <= now => {
                    tracing::info!(
                        parent: span,
                        event = "delivery-expired",
                        domain = domain.domain,
                        reason = "Queue rate limit exceeded.",
                    );

                    for rcpt in &mut self.recipients {
                        if rcpt.domain_idx == idx {
                            rcpt.status = std::mem::replace(&mut rcpt.status, Status::Scheduled)
                                .into_permanent();
                        }
                    }

                    domain.status = Status::PermanentFailure(Error::Io(
                        "Queue rate limit exceeded.".to_string(),
                    ));
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
        if matches!(
            &self.status,
            Status::TemporaryFailure(_) | Status::Scheduled
        ) {
            self.retry(schedule);
        }
    }

    pub fn retry(&mut self, schedule: &[Duration]) {
        self.retry.due = now()
            + schedule[std::cmp::min(self.retry.inner as usize, schedule.len() - 1)].as_secs();
        self.retry.inner += 1;
    }
}
