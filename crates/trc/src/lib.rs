/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod channel;
pub mod collector;
pub mod conv;
pub mod imple;
pub mod macros;
pub mod subscriber;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
#[repr(usize)]
pub enum Level {
    Disable = 0,
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warn = 4,
    Error = 5,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    NewConnection,
    Error(Cause),
    SqlQuery,
    LdapQuery,
    Purge(PurgeEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PurgeEvent {
    Started,
    Finished,
    Running,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    Store(StoreCause),
    Jmap(JmapCause),
    Imap,
    ManageSieve,
    Pop3,
    Smtp,
    Thread,
    Acme,
    Dns,
    Ingest,
    Network,
    Limit(LimitCause),
    Manage(ManageCause),
    Auth(AuthCause),
    Configuration,
    Resource(ResourceCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreCause {
    AssertValue = 0,
    BlobMissingMarker = 1,
    FoundationDB = 2,
    MySQL = 3,
    PostgreSQL = 4,
    RocksDB = 5,
    SQLite = 6,
    Ldap = 7,
    ElasticSearch = 8,
    Redis = 9,
    S3 = 10,
    Filesystem = 11,
    Pool = 12,
    DataCorruption = 13,
    Decompress = 14,
    Deserialize = 15,
    NotFound = 16,
    NotConfigured = 17,
    NotSupported = 18,
    Unexpected = 19,
    Crypto = 20,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JmapCause {
    // Method errors
    InvalidArguments = 0,
    RequestTooLarge = 1,
    StateMismatch = 2,
    AnchorNotFound = 3,
    UnsupportedFilter = 4,
    UnsupportedSort = 5,
    UnknownMethod = 6,
    InvalidResultReference = 7,
    Forbidden = 8,
    AccountNotFound = 9,
    AccountNotSupportedByMethod = 10,
    AccountReadOnly = 11,
    NotFound = 12,
    CannotCalculateChanges = 13,
    UnknownDataType = 14,

    // Request errors
    UnknownCapability = 15,
    NotJSON = 16,
    NotRequest = 17,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitCause {
    SizeRequest = 0,
    SizeUpload = 1,
    CallsIn = 2,
    ConcurrentRequest = 3,
    ConcurrentUpload = 4,
    Quota = 5,
    BlobQuota = 6,
    TooManyRequests = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManageCause {
    MissingParameter = 0,
    AlreadyExists = 1,
    AssertFailed = 2,
    NotFound = 3,
    NotSupported = 4,
    Error = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthCause {
    Failed = 0,
    MissingTotp = 1,
    TooManyAttempts = 2,
    Banned = 3,
    Error = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceCause {
    NotFound = 0,
    BadParameters = 1,
    Error = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Jmap,
    Imap,
    Smtp,
    ManageSieve,
    Ldap,
    Sql,
}

#[derive(Debug, Clone)]
pub struct Error {
    inner: Cause,
    keys: Vec<(Key, Value)>,
}

#[derive(Debug, Clone)]
pub struct Event {
    inner: EventType,
    level: Level,
    keys: Vec<(Key, Value)>,
}

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}
