/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod conv;
pub mod imple;
pub mod macros;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Context<Cause, ERROR_CONTEXT_SIZE>;
pub type Trace = Context<Event, TRACE_CONTEXT_SIZE>;

const ERROR_CONTEXT_SIZE: usize = 5;
const TRACE_CONTEXT_SIZE: usize = 10;

#[derive(Debug, Default, Clone)]
pub enum Value {
    Static(&'static str),
    String(String),
    UInt(u64),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Bool(bool),
    Ipv4(Ipv4Addr),
    Ipv6(Box<Ipv6Addr>),
    Protocol(Protocol),
    Error(Box<Error>),
    Array(Vec<Value>),
    #[default]
    None,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    RemoteIp,
    #[default]
    CausedBy,
    Reason,
    Details,
    Query,
    Result,
    Parameters,
    Type,
    Id,
    Code,
    Key,
    Value,
    Size,
    Status,
    Total,
    Protocol,
    Property,
    Path,
    Url,
    DocumentId,
    Collection,
    AccountId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    NewConnection,
    Error(Cause),
    SqlQuery,
    LdapQuery,
    PurgeTaskStarted,
    PurgeTaskRunning,
    PurgeTaskFinished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Store(StoreCause),
    Jmap(JmapCause),
    Imap,
    ManageSieve,
    Pop3,
    Smtp,
    Thread,
    Fetch,
    Acme,
    Dns,
    Ingest,
    Network,
    Limit(LimitCause),
    Manage(ManageCause),
    Auth(AuthCause),
    Purge,
    Configuration,
    Resource(ResourceCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreCause {
    AssertValue,
    BlobMissingMarker,
    FoundationDB,
    MySQL,
    PostgreSQL,
    RocksDB,
    SQLite,
    Ldap,
    ElasticSearch,
    Redis,
    S3,
    Filesystem,
    Pool,
    DataCorruption,
    Decompress,
    Deserialize,
    NotFound,
    NotConfigured,
    NotSupported,
    Unexpected,
    Crypto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JmapCause {
    // Method errors
    InvalidArguments,
    RequestTooLarge,
    StateMismatch,
    AnchorNotFound,
    UnsupportedFilter,
    UnsupportedSort,
    UnknownMethod,
    InvalidResultReference,
    Forbidden,
    AccountNotFound,
    AccountNotSupportedByMethod,
    AccountReadOnly,
    NotFound,
    CannotCalculateChanges,
    UnknownDataType,

    // Request errors
    UnknownCapability,
    NotJSON,
    NotRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitCause {
    SizeRequest,
    SizeUpload,
    CallsIn,
    ConcurrentRequest,
    ConcurrentUpload,
    Quota,
    BlobQuota,
    TooManyRequests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManageCause {
    MissingParameter,
    AlreadyExists,
    AssertFailed,
    NotFound,
    NotSupported,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCause {
    Failed,
    MissingTotp,
    TooManyAttempts,
    Banned,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceCause {
    NotFound,
    BadParameters,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Jmap,
    Imap,
    Smtp,
    ManageSieve,
    Ldap,
    Sql,
}

#[derive(Debug, Clone)]
pub struct Context<T, const N: usize> {
    inner: T,
    keys: [(Key, Value); N],
    keys_size: usize,
}

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}
