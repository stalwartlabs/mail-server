/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{io, sync::Arc, time::SystemTime};

use chrono::{TimeZone, Utc};
use common::{
    config::smtp::{
        report::{AddressMatch, AggregateFrequency},
        resolver::{Policy, Tlsa},
    },
    expr::if_block::IfBlock,
    webhooks::{WebhookPayload, WebhookType},
    USER_AGENT,
};
use mail_auth::{
    common::headers::HeaderWriter,
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{
        tlsrpt::FailureDetails, AuthFailureType, DeliveryResult, Feedback, FeedbackType, Record,
    },
};
use mail_parser::DateTime;

use store::write::{QueueClass, ReportEvent};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::{Session, SMTP},
    inbound::DkimSign,
    queue::{DomainPart, Message},
};

pub mod analysis;
pub mod dkim;
pub mod dmarc;
pub mod scheduler;
pub mod spf;
pub mod tls;

#[derive(Debug)]
pub enum Event {
    Dmarc(Box<DmarcEvent>),
    Tls(Box<TlsEvent>),
    Stop,
}

#[derive(Debug)]
pub struct DmarcEvent {
    pub domain: String,
    pub report_record: Record,
    pub dmarc_record: Arc<Dmarc>,
    pub interval: AggregateFrequency,
}

#[derive(Debug)]
pub struct TlsEvent {
    pub domain: String,
    pub policy: PolicyType,
    pub failure: Option<FailureDetails>,
    pub tls_record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum PolicyType {
    Tlsa(Option<Arc<Tlsa>>),
    Sts(Option<Arc<Policy>>),
    None,
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn new_auth_failure(&self, ft: AuthFailureType, rejected: bool) -> Feedback<'_> {
        Feedback::new(FeedbackType::AuthFailure)
            .with_auth_failure(ft)
            .with_arrival_date(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64,
            )
            .with_source_ip(self.data.remote_ip)
            .with_reporting_mta(&self.hostname)
            .with_user_agent(USER_AGENT)
            .with_delivery_result(if rejected {
                DeliveryResult::Reject
            } else {
                DeliveryResult::Unspecified
            })
    }

    pub fn is_report(&self) -> bool {
        for addr_match in &self.core.core.smtp.report.analysis.addresses {
            for addr in &self.data.rcpt_to {
                match addr_match {
                    AddressMatch::StartsWith(prefix) if addr.address_lcase.starts_with(prefix) => {
                        return true
                    }
                    AddressMatch::EndsWith(suffix) if addr.address_lcase.ends_with(suffix) => {
                        return true
                    }
                    AddressMatch::Equals(value) if addr.address_lcase.eq(value) => return true,
                    _ => (),
                }
            }
        }

        false
    }
}

impl SMTP {
    pub async fn send_report(
        &self,
        from_addr: &str,
        rcpts: impl Iterator<Item = impl AsRef<str>>,
        report: Vec<u8>,
        sign_config: &IfBlock,
        deliver_now: bool,
    ) {
        // Build message
        let from_addr_lcase = from_addr.to_lowercase();
        let from_addr_domain = from_addr_lcase.domain_part().to_string();
        let mut message = self.new_message(from_addr, from_addr_lcase, from_addr_domain);
        for rcpt_ in rcpts {
            message.add_recipient(rcpt_.as_ref(), self).await;
        }

        // Sign message
        let signature = self.sign_message(&mut message, sign_config, &report).await;

        // Schedule delivery at a random time between now and the next 3 hours
        if !deliver_now {
            #[cfg(not(feature = "test_mode"))]
            {
                use rand::Rng;

                let delivery_time = rand::thread_rng().gen_range(0u64..10800u64);
                for domain in &mut message.domains {
                    domain.retry.due += delivery_time;
                    domain.expires += delivery_time;
                    domain.notify.due += delivery_time;
                }
            }
        }

        // Send webhook
        if self
            .core
            .has_webhook_subscribers(WebhookType::OutgoingReport)
        {
            self.inner
                .ipc
                .send_webhook(
                    WebhookType::OutgoingReport,
                    WebhookPayload::MessageAccepted {
                        id: message.id,
                        remote_ip: None,
                        local_port: None,
                        authenticated_as: None,
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
                    },
                )
                .await;
        }

        // Queue message
        message.queue(signature.as_deref(), &report, self).await;
    }

    pub async fn schedule_report(&self, report: impl Into<Event>) {
        if self.inner.report_tx.send(report.into()).await.is_err() {
            tracing::warn!(context = "report", "Channel send failed.");
        }
    }

    pub async fn sign_message(
        &self,
        message: &mut Message,
        config: &IfBlock,
        bytes: &[u8],
    ) -> Option<Vec<u8>> {
        let signers = self
            .core
            .eval_if::<Vec<String>, _>(config, message, message.id)
            .await
            .unwrap_or_default();
        if !signers.is_empty() {
            let mut headers = Vec::with_capacity(64);
            for signer in signers.iter() {
                if let Some(signer) = self.core.get_dkim_signer(signer) {
                    match signer.sign(bytes) {
                        Ok(signature) => {
                            signature.write_header(&mut headers);
                        }
                        Err(err) => {
                            tracing::warn!(
                        context = "dkim",
                        event = "sign-failed",
                        reason = %err);
                        }
                    }
                }
            }
            if !headers.is_empty() {
                return Some(headers);
            }
        }
        None
    }
}

pub trait AggregateTimestamp {
    fn to_timestamp(&self) -> u64;
    fn to_timestamp_(&self, dt: DateTime) -> u64;
    fn as_secs(&self) -> u64;
}

impl AggregateTimestamp for AggregateFrequency {
    fn to_timestamp(&self) -> u64 {
        self.to_timestamp_(DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        ))
    }

    fn to_timestamp_(&self, mut dt: DateTime) -> u64 {
        (match self {
            AggregateFrequency::Hourly => {
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Daily => {
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Weekly => {
                let dow = dt.day_of_week();
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp() - (86400 * dow as i64)
            }
            AggregateFrequency::Never => dt.to_timestamp(),
        }) as u64
    }

    fn as_secs(&self) -> u64 {
        match self {
            AggregateFrequency::Hourly => 3600,
            AggregateFrequency::Daily => 86400,
            AggregateFrequency::Weekly => 7 * 86400,
            AggregateFrequency::Never => 0,
        }
    }
}

impl From<DmarcEvent> for Event {
    fn from(value: DmarcEvent) -> Self {
        Event::Dmarc(Box::new(value))
    }
}

impl From<TlsEvent> for Event {
    fn from(value: TlsEvent) -> Self {
        Event::Tls(Box::new(value))
    }
}

impl From<Arc<Tlsa>> for PolicyType {
    fn from(value: Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value))
    }
}

impl From<Arc<Policy>> for PolicyType {
    fn from(value: Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value))
    }
}

impl From<&Arc<Tlsa>> for PolicyType {
    fn from(value: &Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value.clone()))
    }
}

impl From<&Arc<Policy>> for PolicyType {
    fn from(value: &Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value.clone()))
    }
}

impl From<(&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)> for PolicyType {
    fn from(value: (&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)) -> Self {
        match value {
            (Some(value), _) => PolicyType::Sts(Some(value.clone())),
            (_, Some(value)) => PolicyType::Tlsa(Some(value.clone())),
            _ => PolicyType::None,
        }
    }
}

pub struct SerializedSize {
    bytes_left: usize,
}

impl SerializedSize {
    pub fn new(bytes_left: usize) -> Self {
        Self { bytes_left }
    }
}

impl io::Write for SerializedSize {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        //let c = print!(" (left: {}, buf: {})", self.bytes_left, buf.len());
        let buf_len = buf.len();
        if buf_len <= self.bytes_left {
            self.bytes_left -= buf_len;
            Ok(buf_len)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Size exceeded"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub trait ReportLock {
    fn tls_lock(event: &ReportEvent) -> Self;
    fn dmarc_lock(event: &ReportEvent) -> Self;
}

impl ReportLock for QueueClass {
    fn tls_lock(event: &ReportEvent) -> Self {
        QueueClass::TlsReportHeader(ReportEvent {
            due: event.due,
            policy_hash: 0,
            seq_id: 0,
            domain: event.domain.clone(),
        })
    }

    fn dmarc_lock(event: &ReportEvent) -> Self {
        QueueClass::DmarcReportHeader(ReportEvent {
            due: event.due,
            policy_hash: event.policy_hash,
            seq_id: 0,
            domain: event.domain.clone(),
        })
    }
}
