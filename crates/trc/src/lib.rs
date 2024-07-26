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
pub type Error = Event;

#[derive(Debug, Clone)]
pub struct Event {
    inner: EventType,
    keys: Vec<(Key, Value)>,
}

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
    Timestamp(u64),
    Duration(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Protocol(Protocol),
    Event(Event),
    Array(Vec<Value>),
    Level(Level),
    #[default]
    None,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Level,
    Time,
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
    SpanId,
    ParentSpanId,
    MessageId,
    MailboxId,
    ChangeId,
    BlobId,
    ListenerId,
    Hostname,
    ValidFrom,
    ValidTo,
    Origin,
    Expected,
    Renewal,
    Attempt,
    NextRetry,
    LocalIp,
    LocalPort,
    RemoteIp,
    RemotePort,
    Limit,
    Tls,
    Version,
    Cipher,
    Duration,
    Count,
    Spam,
    MinLearns,
    SpamLearns,
    HamLearns,
    MinBalance,
    Contents,
    Due,
    NextRenewal,
    Expires,
    From,
    To,
    Interval,
    Strict,
    Domain,
    Policy,
    Elapsed,
    RangeFrom,
    RangeTo,
    DmarcPass,
    DmarcQuarantine,
    DmarcReject,
    DmarcNone,
    DkimPass,
    DkimFail,
    DkimNone,
    SpfPass,
    SpfFail,
    SpfNone,
    PolicyType,
    TotalSuccesses,
    TotalFailures,
    Date,
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
    Http(HttpEvent),
    Network(NetworkEvent),
    Limit(LimitEvent),
    Manage(ManageEvent),
    Auth(AuthEvent),
    Config(ConfigEvent),
    Resource(ResourceEvent),
    Arc(ArcEvent),
    Dkim(DkimEvent),
    Dmarc(DmarcEvent),
    Iprev(IprevEvent),
    Dane(DaneEvent),
    Spf(SpfEvent),
    MailAuth(MailAuthEvent),
    Tls(TlsEvent),
    Sieve(SieveEvent),
    Spam(SpamEvent),
    PushSubscription(PushSubscriptionEvent),
    Cluster(ClusterEvent),
    Housekeeper(HousekeeperEvent),
    FtsIndex(FtsIndexEvent),
    Milter(MilterEvent),
    MtaHook(MtaHookEvent),
    Delivery(DeliveryEvent),
    Queue(QueueEvent),
    TlsRpt(TlsRptEvent),
    MtaSts(MtaStsEvent),
    IncomingReport(IncomingReportEvent),
    OutgoingReport(OutgoingReportEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpEvent {
    Error,
    RequestUrl,
    RequestBody,
    ResponseBody,
    XForwardedMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClusterEvent {
    PeerAlive,
    PeerDiscovered,
    PeerOffline,
    PeerSuspected,
    PeerSuspectedIsAlive,
    PeerBackOnline,
    PeerLeaving,
    PeerHasConfigChanges,
    PeerHasListChanges,
    OneOrMorePeersOffline,
    EmptyPacket,
    InvalidPacket,
    DecryptionError,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HousekeeperEvent {
    Start,
    Stop,
    Schedule,
    PurgeAccounts,
    PurgeSessions,
    PurgeStore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FtsIndexEvent {
    Index,
    Locked,
    LockBusy,
    BlobNotFound,
    MetadataNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImapEvent {
    Error,
    RawInput,
    RawOutput,
    IdleStart,
    IdleStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pop3Event {
    Error,
    RawInput,
    RawOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManageSieveEvent {
    Error,
    RawInput,
    RawOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SmtpEvent {
    Error,
    RemoteIdNotFound,
    ConcurrencyLimitExceeded,
    TransferLimitExceeded,
    RateLimitExceeded,
    TimeLimitExceeded,
    MissingAuthDirectory,
    MessageParseFailed,
    MessageTooLarge,
    LoopDetected,
    PipeSuccess,
    PipeError,
    DkimPass,
    DkimFail,
    ArcPass,
    ArcFail,
    SpfEhloPass,
    SpfEhloFail,
    SpfFromPass,
    SpfFromFail,
    DmarcPass,
    DmarcFail,
    IprevPass,
    IprevFail,
    QuotaExceeded,
    TooManyMessages,
    Ehlo,
    InvalidEhlo,
    MailFrom,
    MailboxDoesNotExist,
    RelayNotAllowed,
    RcptTo,
    TooManyInvalidRcpt,
    RawInput,
    RawOutput,
    MissingLocalHostname,
    Vrfy,
    VrfyNotFound,
    VrfyDisabled,
    Expn,
    ExpnNotFound,
    ExpnDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryEvent {
    AttemptStart,
    AttemptEnd,
    Completed,
    Failed,
    AttemptCount,
    MxLookupFailed,
    IpLookupFailed,
    NullMX,
    Connect,
    ConnectError,
    MissingOutboundHostname,
    GreetingFailed,
    EhloRejected,
    AuthFailed,
    MailFromRejected,
    Delivered,
    RcptToRejected,
    RcptToFailed,
    MessageRejected,
    StartTls,
    StartTlsUnavailable,
    StartTlsError,
    StartTlsDisabled,
    ImplicitTlsError,
    TooManyConcurrent,
    DoubleBounce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueueEvent {
    Scheduled,
    Rescheduled,
    LockBusy,
    Locked,
    BlobNotFound,
    RateLimitExceeded,
    ConcurrencyLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncomingReportEvent {
    DmarcReport,
    DmarcReportWithWarnings,
    TlsReport,
    TlsReportWithWarnings,
    AbuseReport,
    AuthFailureReport,
    FraudReport,
    NotSpamReport,
    VirusReport,
    OtherReport,
    MessageParseFailed,
    DmarcParseFailed,
    TlsRpcParseFailed,
    ArfParseFailed,
    DecompressError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutgoingReportEvent {
    SpfReport,
    SpfRateLimited,
    DkimReport,
    DkimRateLimited,
    DmarcReport,
    DmarcRateLimited,
    DmarcAggregateReport,
    TlsAggregate,
    HttpSubmission,
    UnauthorizedReportingAddress,
    ReportingAddressValidationError,
    NotFound,
    SubmissionError,
    NoRecipientsFound,
    LockBusy,
    LockDeleted,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtaStsEvent {
    PolicyFetch,
    PolicyNotFound,
    PolicyFetchError,
    InvalidPolicy,
    NotAuthorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsRptEvent {
    RecordFetch,
    RecordFetchError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaneEvent {
    AuthenticationSuccess,
    AuthenticationFailure,
    NoCertificatesFound,
    CertificateParseError,
    TlsaRecordMatch,
    TlsaRecordFetch,
    TlsaRecordFetchError,
    TlsaRecordNotFound,
    TlsaRecordNotDnssecSigned,
    TlsaRecordInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MilterEvent {
    Read,
    Write,
    ActionAccept,
    ActionDiscard,
    ActionReject,
    ActionTempFail,
    ActionReplyCode,
    ActionConnectionFailure,
    ActionShutdown,
    IoError,
    FrameTooLarge,
    FrameInvalid,
    UnexpectedResponse,
    Timeout,
    TlsInvalidName,
    Disconnected,
    ParseError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtaHookEvent {
    ActionAccept,
    ActionDiscard,
    ActionReject,
    ActionQuarantine,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushSubscriptionEvent {
    Success,
    Error,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpamEvent {
    PyzorError,
    ListUpdated,
    Train,
    TrainBalance,
    TrainError,
    Classify,
    ClassifyError,
    NotEnoughTrainingData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SieveEvent {
    ActionAccept,
    ActionAcceptReplace,
    ActionDiscard,
    ActionReject,
    SendMessage,
    MessageTooLarge,
    ScriptNotFound,
    ListNotFound,
    RuntimeError,
    UnexpectedError,
    NotSupported,
    QuotaExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsEvent {
    Handshake,
    HandshakeError,
    NotConfigured,
    CertificateNotFound,
    NoCertificatesAvailable,
    MultipleCertificatesAvailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkEvent {
    ConnectionStart,
    ConnectionStop,
    ListenStart,
    ListenStop,
    ListenError,
    BindError,
    ReadError,
    WriteError,
    FlushError,
    AcceptError,
    SplitError,
    Timeout,
    Closed,
    ProxyError,
    SetOptError,
    DropBlocked,
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
    OrderStart,
    OrderProcessing,
    OrderCompleted,
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
    ClientSuppliedSNI,
    ClientMissingSNI,
    TlsAlpnReceived,
    TlsAlpnError,
    TokenNotFound,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PurgeEvent {
    Started,
    Finished,
    Running,
    Error,
    PurgeActive,
    AutoExpunge,
    TombstoneCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvalEvent {
    Result,
    Error,
    DirectoryNotFound,
    StoreNotFound,
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
    ImportExternal,
    ExternalKeyIgnored,
    AlreadyUpToDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArcEvent {
    ChainTooLong,
    InvalidInstance,
    InvalidCV,
    HasHeaderTag,
    BrokenChain,
    SealerNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DkimEvent {
    Pass,
    Neutral,
    Fail,
    PermError,
    TempError,
    None,
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
    SignerNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpfEvent {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcEvent {
    Pass,
    Fail,
    PermError,
    TempError,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IprevEvent {
    Pass,
    Fail,
    PermError,
    TempError,
    None,
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

    // Events
    Ingest,
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

    // Not JMAP standard
    WebsocketStart,
    WebsocketStop,
    WebsocketError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitEvent {
    SizeRequest,
    SizeUpload,
    CallsIn,
    ConcurrentRequest,
    ConcurrentUpload,
    ConcurrentConnection, // Used by listener
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
    Success,
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
    DownloadExternal,
    WebadminUnpacked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Jmap,
    Imap,
    Lmtp,
    Smtp,
    ManageSieve,
    Ldap,
    Sql,
    Pop3,
    Http,
    Gossip,
}

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}
