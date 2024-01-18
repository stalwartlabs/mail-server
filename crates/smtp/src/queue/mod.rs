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

use std::{
    fmt::Display,
    net::IpAddr,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};
use smtp_proto::Response;
use utils::listener::limiter::{ConcurrencyLimiter, InFlight};

use crate::core::{eval::*, management, ResolveVariable};

pub mod dsn;
pub mod manager;
pub mod quota;
pub mod serialize;
pub mod spool;
pub mod throttle;

pub type QueueId = u64;

#[derive(Debug)]
pub enum Event {
    Queue(Schedule<Box<Message>>),
    Manage(management::QueueRequest),
    Done(WorkerResult),
    Stop,
}

#[derive(Debug)]
pub enum WorkerResult {
    Done,
    Retry(Schedule<Box<Message>>),
    OnHold(OnHold<Box<Message>>),
}

#[derive(Debug)]
pub struct OnHold<T> {
    pub next_due: Option<Instant>,
    pub limiters: Vec<ConcurrencyLimiter>,
    pub message: T,
}

#[derive(Debug)]
pub struct Schedule<T> {
    pub due: Instant,
    pub inner: T,
}

#[derive(Debug)]
pub struct Message {
    pub id: QueueId,
    pub created: u64,
    pub path: PathBuf,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<Recipient>,
    pub domains: Vec<Domain>,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: usize,
    pub queue_refs: Vec<UsedQuota>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Domain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: Instant,
    pub status: Status<(), Error>,
    pub disable_tls: bool,
    pub changed: bool,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct HostResponse<T> {
    pub hostname: T,
    pub response: Response<String>,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct ErrorDetails {
    pub entity: String,
    pub details: String,
}

pub struct DeliveryAttempt {
    pub span: tracing::Span,
    pub in_flight: Vec<InFlight>,
    pub message: Box<Message>,
}

#[derive(Debug)]
pub struct QuotaLimiter {
    pub max_size: usize,
    pub max_messages: usize,
    pub size: AtomicUsize,
    pub messages: AtomicUsize,
}

#[derive(Debug)]
pub struct UsedQuota {
    id: u64,
    size: usize,
    limiter: Arc<QuotaLimiter>,
}

impl PartialEq for UsedQuota {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.size == other.size
    }
}

impl Eq for UsedQuota {}

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
            due: Instant::now(),
            inner: T::default(),
        }
    }

    pub fn later(duration: Duration) -> Self {
        Schedule {
            due: Instant::now() + duration,
            inner: T::default(),
        }
    }
}

pub struct SimpleEnvelope<'x> {
    pub message: &'x Message,
    pub domain: &'x str,
    pub recipient: &'x str,
}

impl<'x> SimpleEnvelope<'x> {
    pub fn new(message: &'x Message, domain: &'x str) -> Self {
        Self {
            message,
            domain,
            recipient: "",
        }
    }

    pub fn new_rcpt(message: &'x Message, domain: &'x str, recipient: &'x str) -> Self {
        Self {
            message,
            domain,
            recipient,
        }
    }
}

impl<'x> ResolveVariable for SimpleEnvelope<'x> {
    fn resolve_variable(&self, variable: u32) -> utils::expr::Variable<'_> {
        match variable {
            V_SENDER => self.message.return_path_lcase.as_str().into(),
            V_SENDER_DOMAIN => self.message.return_path_domain.as_str().into(),
            V_PRIORITY => self.message.priority.to_string().into(),
            V_RECIPIENT => self.recipient.into(),
            V_RECIPIENT_DOMAIN => self.domain.into(),
            _ => "".into(),
        }
    }
}

pub struct QueueEnvelope<'x> {
    pub message: &'x Message,
    pub domain: &'x str,
    pub mx: &'x str,
    pub remote_ip: IpAddr,
    pub local_ip: IpAddr,
}

impl<'x> ResolveVariable for QueueEnvelope<'x> {
    fn resolve_variable(&self, variable: u32) -> utils::expr::Variable<'x> {
        match variable {
            V_SENDER => self.message.return_path_lcase.as_str().into(),
            V_SENDER_DOMAIN => self.message.return_path_domain.as_str().into(),
            V_RECIPIENT_DOMAIN => self.domain.into(),
            V_MX => self.mx.into(),
            V_PRIORITY => self.message.priority.into(),
            V_REMOTE_IP => self.remote_ip.to_string().into(),
            V_LOCAL_IP => self.local_ip.to_string().into(),
            _ => "".into(),
        }
    }
}

impl ResolveVariable for Message {
    fn resolve_variable(&self, variable: u32) -> utils::expr::Variable<'_> {
        match variable {
            V_SENDER => self.return_path_lcase.as_str().into(),
            V_SENDER_DOMAIN => self.return_path_domain.as_str().into(),
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
    fn resolve_variable(&self, variable: u32) -> utils::expr::Variable<'_> {
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
