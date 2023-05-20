use std::{
    fmt::Display,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use smtp_proto::Response;
use tokio::sync::oneshot;

use crate::listener::limiter::ConcurrencyLimiter;

pub type QueueId = u64;

#[derive(Debug)]
pub enum Event {
    Queue(Schedule<Box<Message>>),
    Manage(QueueRequest),
    Done(WorkerResult),
    Stop,
}

#[derive(Debug)]
pub enum QueueRequest {
    List {
        from: Option<String>,
        to: Option<String>,
        before: Option<Instant>,
        after: Option<Instant>,
        result_tx: oneshot::Sender<Vec<u64>>,
    },
    Status {
        queue_ids: Vec<QueueId>,
        result_tx: oneshot::Sender<Vec<Option<Message>>>,
    },
    Cancel {
        queue_ids: Vec<QueueId>,
        item: Option<String>,
        result_tx: oneshot::Sender<Vec<bool>>,
    },
    Retry {
        queue_ids: Vec<QueueId>,
        item: Option<String>,
        time: Instant,
        result_tx: oneshot::Sender<Vec<bool>>,
    },
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

#[derive(Debug)]
pub struct UsedQuota {
    pub id: u64,
    pub size: usize,
    pub limiter: Arc<QuotaLimiter>,
}

#[derive(Debug)]
pub struct QuotaLimiter {
    pub max_size: usize,
    pub max_messages: usize,
    pub size: AtomicUsize,
    pub messages: AtomicUsize,
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
        other.due.partial_cmp(&self.due)
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
