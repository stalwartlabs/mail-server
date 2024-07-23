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
    Disable,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Default, Clone)]
pub enum Value {
    Static(&'static str),
    String(String),
    UInt(u64),
    Int(i64),
    Float(f64),
    Timestamp(u64),
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
    Name,
    DocumentId,
    Collection,
    AccountId,
    SessionId,
    Hostname,
    ValidFrom,
    ValidTo,
    Origin,
    Expected,
    Renewal,
    Attempt,
    NextRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    Server(ServerEvent),
    Purge(PurgeEvent),
    Eval(EvalEvent),
    Acme(AcmeEvent),
    Store(StoreEvent),
    Jmap(JmapEvent),
    Imap(ImapEvent),
    ManageSieve(ManageSieveEvent),
    Pop3(Pop3Event),
    Smtp(SmtpEvent),
    Network(NetworkEvent),
    Limit(LimitEvent),
    Manage(ManageEvent),
    Auth(AuthEvent),
    Config(ConfigEvent),
    Resource(ResourceEvent),
    Arc(ArcEvent),
    Dkim(DkimEvent),
    MailAuth(MailAuthEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImapEvent {
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pop3Event {
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManageSieveEvent {
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmtpEvent {
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkEvent {
    ReadError,
    WriteError,
    FlushError,
    Timeout,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerEvent {
    Startup,
    Shutdown,
    StartupError,
    ThreadError,
    Licensing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcmeEvent {
    AuthStart,
    AuthPending,
    AuthValid,
    AuthCompleted,
    AuthError,
    AuthTooManyAttempts,
    ProcessCert,
    OrderProcessing,
    OrderReady,
    OrderValid,
    OrderInvalid,
    RenewBackoff,
    DnsRecordCreated,
    DnsRecordCreationFailed,
    DnsRecordDeletionFailed,
    DnsRecordNotPropagated,
    DnsRecordLookupFailed,
    DnsRecordPropagated,
    DnsRecordPropagationTimeout,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PurgeEvent {
    Started,
    Finished,
    Running,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvalEvent {
    Result,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigEvent {
    ParseError,
    BuildError,
    MacroError,
    WriteError,
    FetchError,
    DefaultApplied,
    MissingSetting,
    UnusedSetting,
    ParseWarning,
    BuildWarning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArcEvent {
    ChainTooLong,
    InvalidInstance,
    InvalidCV,
    HasHeaderTag,
    BrokenChain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DkimEvent {
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCanonicalization,
    UnsupportedKeyType,
    FailedBodyHashMatch,
    FailedVerification,
    FailedAuidMatch,
    RevokedPublicKey,
    IncompatibleAlgorithms,
    SignatureExpired,
    SignatureLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MailAuthEvent {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    Crypto,
    Io,
    Base64,
    DnsError,
    DnsRecordNotFound,
    DnsInvalidRecordType,
    PolicyNotAligned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreEvent {
    // Errors
    IngestError,
    AssertValueFailed,
    FoundationDBError,
    MySQLError,
    PostgreSQLError,
    RocksDBError,
    SQLiteError,
    LdapError,
    ElasticSearchError,
    RedisError,
    S3Error,
    FilesystemError,
    PoolError,
    DataCorruption,
    DecompressError,
    DeserializeError,
    NotFound,
    NotConfigured,
    NotSupported,
    UnexpectedError,
    CryptoError,

    // Warnings
    BlobMissingMarker,

    // Traces
    SqlQuery,
    LdapQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JmapEvent {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitEvent {
    SizeRequest,
    SizeUpload,
    CallsIn,
    ConcurrentRequest,
    ConcurrentUpload,
    Quota,
    BlobQuota,
    TooManyRequests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManageEvent {
    MissingParameter,
    AlreadyExists,
    AssertFailed,
    NotFound,
    NotSupported,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthEvent {
    Failed,
    MissingTotp,
    TooManyAttempts,
    Banned,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceEvent {
    NotFound,
    BadParameters,
    Error,
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
    inner: EventType,
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
