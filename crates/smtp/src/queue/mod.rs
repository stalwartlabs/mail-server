/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant, SystemTime},
};

use common::{
    expr::{self, functions::ResolveVariable, *},
    listener::limiter::{ConcurrencyLimiter, InFlight},
};
use serde::{Deserialize, Serialize};
use smtp_proto::Response;
use store::write::now;
use utils::BlobHash;

use self::spool::QueueEventLock;

pub mod dsn;
pub mod manager;
pub mod quota;
pub mod spool;
pub mod throttle;

pub type QueueId = u64;

#[derive(Debug)]
pub enum Event {
    Reload,
    OnHold(OnHold<QueueEventLock>),
    Stop,
}

#[derive(Debug)]
pub struct OnHold<T> {
    pub next_due: Option<u64>,
    pub limiters: Vec<ConcurrencyLimiter>,
    pub message: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule<T> {
    pub due: u64,
    pub inner: T,
}

#[derive(Debug, Clone, Copy)]
pub enum MessageSource {
    Authenticated,
    Unauthenticated,
    Dsn,
    Report,
    Sieve,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    pub queue_id: QueueId,
    pub created: u64,
    pub blob_hash: BlobHash,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<Recipient>,
    pub domains: Vec<Domain>,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: usize,
    pub quota_keys: Vec<QuotaKey>,

    #[serde(skip)]
    pub span_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuotaKey {
    Size { key: Vec<u8>, id: u64 },
    Count { key: Vec<u8>, id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: u64,
    pub status: Status<(), Error>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status<HostResponse<String>, HostResponse<ErrorDetails>>,
    pub flags: u64,
    pub orcpt: Option<String>,
}

pub const RCPT_DSN_SENT: u64 = 1 << 32;
pub const RCPT_STATUS_CHANGED: u64 = 2 << 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status<T, E> {
    #[serde(rename = "scheduled")]
    Scheduled,
    #[serde(rename = "completed")]
    Completed(T),
    #[serde(rename = "temp_fail")]
    TemporaryFailure(E),
    #[serde(rename = "perm_fail")]
    PermanentFailure(E),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostResponse<T> {
    pub hostname: T,
    pub response: Response<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    DnsError(String),
    UnexpectedResponse(HostResponse<ErrorDetails>),
    ConnectionError(ErrorDetails),
    TlsError(ErrorDetails),
    DaneError(ErrorDetails),
    MtaStsError(String),
    RateLimited,
    ConcurrencyLimited,
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ErrorDetails {
    pub entity: String,
    pub details: String,
}

pub struct DeliveryAttempt {
    pub in_flight: Vec<InFlight>,
    pub event: QueueEventLock,
}

impl<T> Ord for Schedule<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.due.cmp(&self.due)
    }
}

impl<T> PartialOrd for Schedule<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> PartialEq for Schedule<T> {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due
    }
}

impl<T> Eq for Schedule<T> {}

impl<T: Default> Schedule<T> {
    pub fn now() -> Self {
        Schedule {
            due: now(),
            inner: T::default(),
        }
    }

    pub fn later(duration: Duration) -> Self {
        Schedule {
            due: now() + duration.as_secs(),
            inner: T::default(),
        }
    }
}

pub struct QueueEnvelope<'x> {
    pub message: &'x Message,
    pub mx: &'x str,
    pub remote_ip: IpAddr,
    pub local_ip: IpAddr,
    pub current_domain: usize,
    pub current_rcpt: usize,
}

impl<'x> QueueEnvelope<'x> {
    pub fn new(message: &'x Message, current_domain: usize) -> Self {
        Self {
            message,
            current_domain,
            current_rcpt: 0,
            mx: "",
            remote_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            local_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }

    pub fn new_rcpt(message: &'x Message, current_domain: usize, current_rcpt: usize) -> Self {
        Self {
            message,
            current_domain,
            current_rcpt,
            mx: "",
            remote_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            local_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl<'x> QueueEnvelope<'x> {
    fn current_domain(&self) -> Option<&'x Domain> {
        self.message.domains.get(self.current_domain)
    }
}

impl<'x> ResolveVariable for QueueEnvelope<'x> {
    fn resolve_variable(&self, variable: u32) -> expr::Variable<'x> {
        match variable {
            V_SENDER => self.message.return_path_lcase.as_str().into(),
            V_SENDER_DOMAIN => self.message.return_path_domain.as_str().into(),
            V_RECIPIENT_DOMAIN => self
                .current_domain()
                .map(|d| d.domain.as_str())
                .unwrap_or_default()
                .into(),
            V_RECIPIENT => self
                .message
                .recipients
                .get(self.current_rcpt)
                .map(|r| r.address_lcase.as_str())
                .unwrap_or_default()
                .into(),
            V_RECIPIENTS => self
                .message
                .recipients
                .iter()
                .map(|r| Variable::from(r.address_lcase.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_QUEUE_RETRY_NUM => self
                .current_domain()
                .map(|d| d.retry.inner)
                .unwrap_or_default()
                .into(),
            V_QUEUE_NOTIFY_NUM => self
                .current_domain()
                .map(|d| d.notify.inner)
                .unwrap_or_default()
                .into(),
            V_QUEUE_EXPIRES_IN => self
                .current_domain()
                .map(|d| d.expires.saturating_sub(now()))
                .unwrap_or_default()
                .into(),
            V_QUEUE_LAST_STATUS => self
                .current_domain()
                .map(|d| d.status.to_string())
                .unwrap_or_default()
                .into(),
            V_QUEUE_LAST_ERROR => self
                .current_domain()
                .map(|d| match &d.status {
                    Status::Scheduled | Status::Completed(_) => "none",
                    Status::TemporaryFailure(err) | Status::PermanentFailure(err) => match err {
                        Error::DnsError(_) => "dns",
                        Error::UnexpectedResponse(_) => "unexpected-reply",
                        Error::ConnectionError(_) => "connection",
                        Error::TlsError(_) => "tls",
                        Error::DaneError(_) => "dane",
                        Error::MtaStsError(_) => "mta-sts",
                        Error::RateLimited => "rate",
                        Error::ConcurrencyLimited => "concurrency",
                        Error::Io(_) => "io",
                    },
                })
                .unwrap_or_default()
                .into(),
            V_MX => self.mx.into(),
            V_PRIORITY => self.message.priority.into(),
            V_REMOTE_IP => self.remote_ip.to_string().into(),
            V_LOCAL_IP => self.local_ip.to_string().into(),
            _ => "".into(),
        }
    }
}

impl ResolveVariable for Message {
    fn resolve_variable(&self, variable: u32) -> expr::Variable<'_> {
        match variable {
            V_SENDER => self.return_path_lcase.as_str().into(),
            V_SENDER_DOMAIN => self.return_path_domain.as_str().into(),
            V_RECIPIENTS => self
                .recipients
                .iter()
                .map(|r| Variable::from(r.address_lcase.as_str()))
                .collect::<Vec<_>>()
                .into(),
            V_PRIORITY => self.priority.into(),
            _ => "".into(),
        }
    }
}

pub struct RecipientDomain<'x>(&'x str);

impl<'x> RecipientDomain<'x> {
    pub fn new(domain: &'x str) -> Self {
        Self(domain)
    }
}

impl<'x> ResolveVariable for RecipientDomain<'x> {
    fn resolve_variable(&self, variable: u32) -> expr::Variable<'x> {
        match variable {
            V_RECIPIENT_DOMAIN => self.0.into(),
            _ => "".into(),
        }
    }
}

#[inline(always)]
pub fn instant_to_timestamp(now: Instant, time: Instant) -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        + time.checked_duration_since(now).map_or(0, |d| d.as_secs())
}

pub trait InstantFromTimestamp {
    fn to_instant(&self) -> Instant;
}

impl InstantFromTimestamp for u64 {
    fn to_instant(&self) -> Instant {
        let timestamp = *self;
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if timestamp > current_timestamp {
            Instant::now() + Duration::from_secs(timestamp - current_timestamp)
        } else {
            Instant::now()
        }
    }
}

pub trait DomainPart {
    fn domain_part(&self) -> &str;
}

impl DomainPart for &str {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

impl DomainPart for String {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedResponse(response) => {
                write!(
                    f,
                    "Unexpected response from '{}': {}",
                    response.hostname.entity, response.response
                )
            }
            Error::DnsError(err) => {
                write!(f, "DNS lookup failed: {err}")
            }
            Error::ConnectionError(details) => {
                write!(
                    f,
                    "Connection to '{}' failed: {}",
                    details.entity, details.details
                )
            }
            Error::TlsError(details) => {
                write!(
                    f,
                    "TLS error from '{}': {}",
                    details.entity, details.details
                )
            }
            Error::DaneError(details) => {
                write!(
                    f,
                    "DANE failed to authenticate '{}': {}",
                    details.entity, details.details
                )
            }
            Error::MtaStsError(details) => {
                write!(f, "MTA-STS auth failed: {details}")
            }
            Error::RateLimited => {
                write!(f, "Rate limited")
            }
            Error::ConcurrencyLimited => {
                write!(f, "Too many concurrent connections to remote server")
            }
            Error::Io(err) => {
                write!(f, "Queue error: {err}")
            }
        }
    }
}

impl Display for Status<(), Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Scheduled => write!(f, "Scheduled"),
            Status::Completed(_) => write!(f, "Completed"),
            Status::TemporaryFailure(err) => write!(f, "Temporary Failure: {err}"),
            Status::PermanentFailure(err) => write!(f, "Permanent Failure: {err}"),
        }
    }
}

impl Display for Status<HostResponse<String>, HostResponse<ErrorDetails>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Scheduled => write!(f, "Scheduled"),
            Status::Completed(response) => write!(f, "Delivered: {}", response.response),
            Status::TemporaryFailure(err) => write!(f, "Temporary Failure: {}", err.response),
            Status::PermanentFailure(err) => write!(f, "Permanent Failure: {}", err.response),
        }
    }
}
