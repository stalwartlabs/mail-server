/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bitset;
pub mod channel;
pub mod collector;
pub mod conv;
pub mod fmt;
pub mod imple;
pub mod macros;
pub mod serializer;
pub mod subscriber;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use event_macro::{camel_names, event_family, event_type, total_event_count};

pub type Result<T> = std::result::Result<T, Error>;
pub type Error = Event<EventType>;

#[derive(Debug, Clone)]
pub struct Event<T> {
    pub inner: T,
    pub keys: Vec<(Key, Value)>,
}

#[derive(Debug, Clone)]
pub struct EventDetails {
    pub typ: EventType,
    pub timestamp: u64,
    pub level: Level,
    pub span: Option<Arc<Event<EventDetails>>>,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
#[repr(usize)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Disable = 5,
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
    Event(Event<EventType>),
    Array(Vec<Value>),
    #[default]
    None,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[camel_names]
pub enum Key {
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
    Used,
    Name,
    OldName,
    DocumentId,
    Collection,
    AccountId,
    QueueId,
    SpanId,
    ReportId,
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
    NextDsn,
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
    Uid,
    UidValidity,
    UidNext,
    SourceAccountId,
    SourceMailboxId,
    SourceUid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[event_family]
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
    Tracing(TracingEvent),
}

#[event_type]
pub enum HttpEvent {
    Error,
    RequestUrl,
    RequestBody,
    ResponseBody,
    XForwardedMissing,
}

#[event_type]
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

#[event_type]
pub enum HousekeeperEvent {
    Start,
    Stop,
    Schedule,
    PurgeAccounts,
    PurgeSessions,
    PurgeStore,
}

#[event_type]
pub enum FtsIndexEvent {
    Index,
    Locked,
    LockBusy,
    BlobNotFound,
    MetadataNotFound,
}

#[event_type]
pub enum ImapEvent {
    // Commands
    GetAcl,
    SetAcl,
    MyRights,
    ListRights,
    Append,
    Capabilities,
    Id,
    Close,
    Copy,
    Move,
    CreateMailbox,
    DeleteMailbox,
    RenameMailbox,
    Enable,
    Expunge,
    Fetch,
    IdleStart,
    IdleStop,
    List,
    Lsub,
    Logout,
    Namespace,
    Noop,
    Search,
    Sort,
    Select,
    Status,
    Store,
    Subscribe,
    Unsubscribe,
    Thread,

    // Errors
    Error,

    // Debugging
    RawInput,
    RawOutput,
}

#[event_type]
pub enum Pop3Event {
    // Commands
    Delete,
    Reset,
    Quit,
    Fetch,
    List,
    ListMessage,
    Uidl,
    UidlMessage,
    Stat,
    Noop,
    Capabilities,
    StartTls,
    Utf8,

    // Errors
    Error,

    // Debugging
    RawInput,
    RawOutput,
}

#[event_type]
pub enum ManageSieveEvent {
    // Commands
    CreateScript,
    UpdateScript,
    GetScript,
    DeleteScript,
    RenameScript,
    CheckScript,
    HaveSpace,
    ListScripts,
    SetActive,
    Capabilities,
    StartTls,
    Unauthenticate,
    Logout,
    Noop,

    // Errors
    Error,

    // Debugging
    RawInput,
    RawOutput,
}

#[event_type]
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
    TooManyMessages,
    Ehlo,
    InvalidEhlo,
    DidNotSayEhlo,
    EhloExpected,
    LhloExpected,
    MailFromUnauthenticated,
    MailFromUnauthorized,
    MailFromRewritten,
    MailFromMissing,
    MailFrom,
    MultipleMailFrom,
    MailboxDoesNotExist,
    RelayNotAllowed,
    RcptTo,
    RcptToDuplicate,
    RcptToRewritten,
    RcptToMissing,
    TooManyRecipients,
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
    RequireTlsDisabled,
    DeliverByDisabled,
    DeliverByInvalid,
    FutureReleaseDisabled,
    FutureReleaseInvalid,
    MtPriorityDisabled,
    MtPriorityInvalid,
    DsnDisabled,
    AuthNotAllowed,
    AuthMechanismNotSupported,
    AuthExchangeTooLong,
    AlreadyAuthenticated,
    Noop,
    StartTls,
    StartTlsUnavailable,
    StartTlsAlready,
    Rset,
    Quit,
    Help,
    CommandNotImplemented,
    InvalidCommand,
    InvalidSenderAddress,
    InvalidRecipientAddress,
    InvalidParameter,
    UnsupportedParameter,
    SyntaxError,
    RequestTooLarge,
}

#[event_type]
pub enum DeliveryEvent {
    AttemptStart,
    AttemptEnd,
    Completed,
    Failed,
    DomainDeliveryStart,
    MxLookup,
    MxLookupFailed,
    IpLookup,
    IpLookupFailed,
    NullMx,
    Connect,
    ConnectError,
    MissingOutboundHostname,
    GreetingFailed,
    Ehlo,
    EhloRejected,
    Auth,
    AuthFailed,
    MailFrom,
    MailFromRejected,
    Delivered,
    RcptTo,
    RcptToRejected,
    RcptToFailed,
    MessageRejected,
    StartTls,
    StartTlsUnavailable,
    StartTlsError,
    StartTlsDisabled,
    ImplicitTlsError,
    ConcurrencyLimitExceeded,
    RateLimitExceeded,
    DoubleBounce,
    DsnSuccess,
    DsnTempFail,
    DsnPermFail,
    RawInput,
    RawOutput,
}

#[event_type]
pub enum QueueEvent {
    Scheduled,
    Rescheduled,
    LockBusy,
    Locked,
    BlobNotFound,
    RateLimitExceeded,
    ConcurrencyLimitExceeded,
    QuotaExceeded,
}

#[event_type]
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

#[event_type]
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

#[event_type]
pub enum MtaStsEvent {
    Authorized,
    NotAuthorized,
    PolicyFetch,
    PolicyNotFound,
    PolicyFetchError,
    InvalidPolicy,
}

#[event_type]
pub enum TlsRptEvent {
    RecordFetch,
    RecordFetchError,
}

#[event_type]
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

#[event_type]
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

#[event_type]
pub enum MtaHookEvent {
    ActionAccept,
    ActionDiscard,
    ActionReject,
    ActionQuarantine,
    Error,
}

#[event_type]
pub enum PushSubscriptionEvent {
    Success,
    Error,
    NotFound,
}

#[event_type]
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

#[event_type]
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

#[event_type]
pub enum TlsEvent {
    Handshake,
    HandshakeError,
    NotConfigured,
    CertificateNotFound,
    NoCertificatesAvailable,
    MultipleCertificatesAvailable,
}

#[event_type]
pub enum NetworkEvent {
    ConnectionStart,
    ConnectionEnd,
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

#[event_type]
pub enum ServerEvent {
    Startup,
    Shutdown,
    StartupError,
    ThreadError,
    Licensing,
}

#[event_type]
pub enum TracingEvent {
    Update,
    LogError,
    WebhookError,
    OtelError,
    JournalError,
}

#[event_type]
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
    ClientSuppliedSni,
    ClientMissingSni,
    TlsAlpnReceived,
    TlsAlpnError,
    TokenNotFound,
    Error,
}

#[event_type]
pub enum PurgeEvent {
    Started,
    Finished,
    Running,
    Error,
    PurgeActive,
    AutoExpunge,
    TombstoneCleanup,
}

#[event_type]
pub enum EvalEvent {
    Result,
    Error,
    DirectoryNotFound,
    StoreNotFound,
}

#[event_type]
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

#[event_type]
pub enum ArcEvent {
    ChainTooLong,
    InvalidInstance,
    InvalidCv,
    HasHeaderTag,
    BrokenChain,
    SealerNotFound,
}

#[event_type]
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

#[event_type]
pub enum SpfEvent {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    TempError,
    PermError,
    None,
}

#[event_type]
pub enum DmarcEvent {
    Pass,
    Fail,
    PermError,
    TempError,
    None,
}

#[event_type]
pub enum IprevEvent {
    Pass,
    Fail,
    PermError,
    TempError,
    None,
}

#[event_type]
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

#[event_type]
pub enum StoreEvent {
    // Errors
    IngestError,
    AssertValueFailed,
    FoundationdbError,
    MysqlError,
    PostgresqlError,
    RocksdbError,
    SqliteError,
    LdapError,
    ElasticsearchError,
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
    LdapBind,

    // Events
    Ingest,
    IngestDuplicate,
}

#[event_type]
pub enum JmapEvent {
    // Calls
    MethodCall,

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
    NotJson,
    NotRequest,

    // Not JMAP standard
    WebsocketStart,
    WebsocketStop,
    WebsocketError,
}

#[event_type]
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

#[event_type]
pub enum ManageEvent {
    MissingParameter,
    AlreadyExists,
    AssertFailed,
    NotFound,
    NotSupported,
    Error,
}

#[event_type]
pub enum AuthEvent {
    Success,
    Failed,
    MissingTotp,
    TooManyAttempts,
    Banned,
    Error,
}

#[event_type]
pub enum ResourceEvent {
    NotFound,
    BadParameters,
    Error,
    DownloadExternal,
    WebadminUnpacked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[camel_names]
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

pub const TOTAL_EVENT_COUNT: usize = total_event_count!();

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}
