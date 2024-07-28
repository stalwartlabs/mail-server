/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, cmp::Ordering, fmt::Display, str::FromStr, time::SystemTime};

use crate::*;

impl Event {
    pub fn with_capacity(inner: EventType, capacity: usize) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(capacity + 2),
        }
    }

    pub fn new(inner: EventType) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(5),
        }
    }

    pub fn with_level(mut self, level: Level) -> Self {
        let level = (Key::Level, level.into());
        let time = (
            Key::Time,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .into(),
        );

        if self.keys.is_empty() {
            self.keys.push(level);
            self.keys.push(time);
        } else {
            let mut keys = Vec::with_capacity(self.keys.len() + 2);
            keys.push(level);
            keys.push(time);
            keys.append(&mut self.keys);
            self.keys = keys;
        }
        self
    }

    #[inline(always)]
    pub fn ctx(mut self, key: Key, value: impl Into<Value>) -> Self {
        self.keys.push((key, value.into()));
        self
    }

    #[inline(always)]
    pub fn ctx_unique(mut self, key: Key, value: impl Into<Value>) -> Self {
        if self.keys.iter().all(|(k, _)| *k != key) {
            self.keys.push((key, value.into()));
        }
        self
    }

    #[inline(always)]
    pub fn ctx_opt(self, key: Key, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.ctx(key, value),
            None => self,
        }
    }

    #[inline(always)]
    pub fn matches(&self, inner: EventType) -> bool {
        self.inner == inner
    }

    #[inline(always)]
    pub fn level(&self) -> Level {
        if let Some((_, Value::Level(level))) = self.keys.first() {
            *level
        } else {
            debug_assert!(false, "Event has no level");
            Level::Disable
        }
    }

    pub fn value(&self, key: Key) -> Option<&Value> {
        self.keys
            .iter()
            .find_map(|(k, v)| if *k == key { Some(v) } else { None })
    }

    pub fn value_as_str(&self, key: Key) -> Option<&str> {
        self.value(key).and_then(|v| v.as_str())
    }

    pub fn take_value(&mut self, key: Key) -> Option<Value> {
        self.keys.iter_mut().find_map(|(k, v)| {
            if *k == key {
                Some(std::mem::take(v))
            } else {
                None
            }
        })
    }

    #[inline(always)]
    pub fn span_id(self, session_id: u64) -> Self {
        self.ctx(Key::SpanId, session_id)
    }
    #[inline(always)]
    pub fn parent_span_id(self, session_id: u64) -> Self {
        self.ctx(Key::ParentSpanId, session_id)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::CausedBy, error)
    }

    #[inline(always)]
    pub fn details(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Details, error)
    }

    #[inline(always)]
    pub fn code(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Code, error)
    }

    #[inline(always)]
    pub fn id(self, error: impl Into<Value>) -> Self {
        self.ctx(Key::Id, error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Self {
        self.ctx(Key::Reason, error.to_string())
    }

    #[inline(always)]
    pub fn protocol(self, protocol: Protocol) -> Self {
        self.ctx(Key::Protocol, protocol)
    }

    #[inline(always)]
    pub fn document_id(self, id: u32) -> Self {
        self.ctx(Key::DocumentId, id)
    }

    #[inline(always)]
    pub fn account_id(self, id: u32) -> Self {
        self.ctx(Key::AccountId, id)
    }

    #[inline(always)]
    pub fn collection(self, id: impl Into<u8>) -> Self {
        self.ctx(Key::Collection, id.into() as u64)
    }

    #[inline(always)]
    pub fn property(self, id: impl Into<u8>) -> Self {
        self.ctx(Key::Property, id.into() as u64)
    }

    #[inline(always)]
    pub fn wrap(self, cause: EventType) -> Self {
        Error::new(cause).caused_by(self)
    }

    #[inline(always)]
    pub fn is_assertion_failure(&self) -> bool {
        self.inner == EventType::Store(StoreEvent::AssertValueFailed)
    }

    #[inline(always)]
    pub fn is_jmap_method_error(&self) -> bool {
        !matches!(
            self.inner,
            EventType::Jmap(
                JmapEvent::UnknownCapability | JmapEvent::NotJSON | JmapEvent::NotRequest
            )
        )
    }

    #[inline(always)]
    pub fn must_disconnect(&self) -> bool {
        matches!(
            self.inner,
            EventType::Network(_)
                | EventType::Auth(AuthEvent::TooManyAttempts | AuthEvent::Banned)
                | EventType::Limit(LimitEvent::ConcurrentRequest | LimitEvent::TooManyRequests)
        )
    }

    #[inline(always)]
    pub fn should_write_err(&self) -> bool {
        !matches!(
            self.inner,
            EventType::Network(_) | EventType::Auth(AuthEvent::Banned)
        )
    }

    pub fn corrupted_key(key: &[u8], value: Option<&[u8]>, caused_by: &'static str) -> Error {
        EventType::Store(StoreEvent::DataCorruption)
            .ctx(Key::Key, key)
            .ctx_opt(Key::Value, value)
            .ctx(Key::CausedBy, caused_by)
    }
}

impl EventType {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(self)
    }

    pub fn message(&self) -> &'static str {
        match self {
            EventType::Store(cause) => cause.message(),
            EventType::Jmap(cause) => cause.message(),
            EventType::Imap(_) => "IMAP error",
            EventType::ManageSieve(_) => "ManageSieve error",
            EventType::Pop3(_) => "POP3 error",
            EventType::Smtp(_) => "SMTP error",
            EventType::Network(_) => "Network error",
            EventType::Limit(cause) => cause.message(),
            EventType::Manage(cause) => cause.message(),
            EventType::Auth(cause) => cause.message(),
            EventType::Config(_) => "Configuration error",
            EventType::Resource(cause) => cause.message(),
            _ => "Internal server error",
        }
    }
}

impl StoreEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Store(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::AssertValueFailed => "Another process has modified the value",
            Self::BlobMissingMarker => "Blob is missing marker",
            Self::FoundationDBError => "FoundationDB error",
            Self::MySQLError => "MySQL error",
            Self::PostgreSQLError => "PostgreSQL error",
            Self::RocksDBError => "RocksDB error",
            Self::SQLiteError => "SQLite error",
            Self::LdapError => "LDAP error",
            Self::ElasticSearchError => "ElasticSearch error",
            Self::RedisError => "Redis error",
            Self::S3Error => "S3 error",
            Self::FilesystemError => "Filesystem error",
            Self::PoolError => "Connection pool error",
            Self::DataCorruption => "Data corruption",
            Self::DecompressError => "Decompression error",
            Self::DeserializeError => "Deserialization error",
            Self::NotFound => "Not found",
            Self::NotConfigured => "Not configured",
            Self::NotSupported => "Operation not supported",
            Self::UnexpectedError => "Unexpected error",
            Self::CryptoError => "Crypto error",
            Self::IngestError => "Message Ingest error",
            _ => "Store error",
        }
    }
}

impl AuthEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Auth(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Failed => "Authentication failed",
            Self::MissingTotp => concat!(
                "A TOTP code is required to authenticate this account. ",
                "Try authenticating again using 'secret$totp_token'."
            ),
            Self::TooManyAttempts => "Too many authentication attempts",
            Self::Banned => "Banned",
            _ => "Authentication error",
        }
    }
}

impl ManageEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Manage(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::MissingParameter => "Missing parameter",
            Self::AlreadyExists => "Already exists",
            Self::AssertFailed => "Assertion failed",
            Self::NotFound => "Not found",
            Self::NotSupported => "Operation not supported",
            Self::Error => "Management API Error",
        }
    }
}

impl JmapEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Jmap(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "Invalid arguments",
            Self::RequestTooLarge => "Request too large",
            Self::StateMismatch => "State mismatch",
            Self::AnchorNotFound => "Anchor not found",
            Self::UnsupportedFilter => "Unsupported filter",
            Self::UnsupportedSort => "Unsupported sort",
            Self::UnknownMethod => "Unknown method",
            Self::InvalidResultReference => "Invalid result reference",
            Self::Forbidden => "Forbidden",
            Self::AccountNotFound => "Account not found",
            Self::AccountNotSupportedByMethod => "Account not supported by method",
            Self::AccountReadOnly => "Account read-only",
            Self::NotFound => "Not found",
            Self::CannotCalculateChanges => "Cannot calculate changes",
            Self::UnknownDataType => "Unknown data type",
            Self::UnknownCapability => "Unknown capability",
            Self::NotJSON => "Not JSON",
            Self::NotRequest => "Not a request",
            _ => "Other message",
        }
    }
}

impl LimitEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Limit(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::SizeRequest => "Request too large",
            Self::SizeUpload => "Upload too large",
            Self::CallsIn => "Too many calls in",
            Self::ConcurrentRequest => "Too many concurrent requests",
            Self::ConcurrentConnection => "Too many concurrent connections",
            Self::ConcurrentUpload => "Too many concurrent uploads",
            Self::Quota => "Quota exceeded",
            Self::BlobQuota => "Blob quota exceeded",
            Self::TooManyRequests => "Too many requests",
        }
    }
}

impl ResourceEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Resource(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "Not found",
            Self::BadParameters => "Bad parameters",
            Self::Error => "Resource error",
            _ => "Other status",
        }
    }
}

impl SmtpEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Smtp(self))
    }
}

impl SieveEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Sieve(self))
    }
}

impl SpamEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Spam(self))
    }
}

impl ImapEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Imap(self))
    }

    #[inline(always)]
    pub fn caused_by(self, error: impl Into<Value>) -> Error {
        self.into_err().caused_by(error)
    }

    #[inline(always)]
    pub fn reason(self, error: impl Display) -> Error {
        self.into_err().reason(error)
    }
}

impl Pop3Event {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Pop3(self))
    }
}

impl ManageSieveEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::ManageSieve(self))
    }
}

impl NetworkEvent {
    #[inline(always)]
    pub fn ctx(self, key: Key, value: impl Into<Value>) -> Error {
        self.into_err().ctx(key, value)
    }

    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Network(self))
    }
}

impl Value {
    pub fn from_maybe_string(value: &[u8]) -> Self {
        if let Ok(value) = std::str::from_utf8(value) {
            Self::String(value.to_string())
        } else {
            Self::Bytes(value.to_vec())
        }
    }

    pub fn to_uint(&self) -> Option<u64> {
        match self {
            Self::UInt(value) => Some(*value),
            Self::Int(value) => Some(*value as u64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            Self::Static(value) => Some(value),
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<Cow<'static, str>> {
        match self {
            Self::String(value) => Some(Cow::Owned(value)),
            Self::Static(value) => Some(Cow::Borrowed(value)),
            _ => None,
        }
    }
}

impl<T> AddContext<T> for Result<T> {
    #[inline(always)]
    fn caused_by(self, location: &'static str) -> Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(err.ctx(Key::CausedBy, location)),
        }
    }

    #[inline(always)]
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error,
    {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(f(err)),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)?;
        for (key, value) in self.keys.iter() {
            write!(f, "\n  {:?} = {:?}", key, value)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl PartialOrd for Level {
    #[inline(always)]
    fn partial_cmp(&self, other: &Level) -> Option<Ordering> {
        Some(self.cmp(other))
    }

    #[inline(always)]
    fn lt(&self, other: &Level) -> bool {
        (*other as usize) < (*self as usize)
    }

    #[inline(always)]
    fn le(&self, other: &Level) -> bool {
        (*other as usize) <= (*self as usize)
    }

    #[inline(always)]
    fn gt(&self, other: &Level) -> bool {
        (*other as usize) > (*self as usize)
    }

    #[inline(always)]
    fn ge(&self, other: &Level) -> bool {
        (*other as usize) >= (*self as usize)
    }
}

impl Ord for Level {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> Ordering {
        (*other as usize).cmp(&(*self as usize))
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Static(l0), Self::Static(r0)) => l0 == r0,
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::String(l0), Self::Static(r0)) => l0 == r0,
            (Self::Static(l0), Self::String(r0)) => l0 == r0,
            (Self::UInt(l0), Self::UInt(r0)) => l0 == r0,
            (Self::Int(l0), Self::Int(r0)) => l0 == r0,
            (Self::Float(l0), Self::Float(r0)) => l0 == r0,
            (Self::Bytes(l0), Self::Bytes(r0)) => l0 == r0,
            (Self::Bool(l0), Self::Bool(r0)) => l0 == r0,
            (Self::Ipv4(l0), Self::Ipv4(r0)) => l0 == r0,
            (Self::Ipv6(l0), Self::Ipv6(r0)) => l0 == r0,
            (Self::Protocol(l0), Self::Protocol(r0)) => l0 == r0,
            (Self::Event(l0), Self::Event(r0)) => l0 == r0,
            (Self::Level(l0), Self::Level(r0)) => l0 == r0,
            (Self::Array(l0), Self::Array(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        if self.inner == other.inner && self.keys.len() == other.keys.len() {
            for kv in self.keys.iter() {
                if !other.keys.iter().any(|okv| kv == okv) {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

impl FromStr for Level {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(s.to_string()),
        }
    }
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disable => "DISABLE",
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

impl Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Eq for Error {}

impl EventType {
    pub fn level(&self) -> Level {
        match self {
            EventType::Store(event) => match event {
                StoreEvent::SqlQuery | StoreEvent::LdapQuery | StoreEvent::LdapBind => Level::Trace,
                StoreEvent::NotFound => Level::Debug,
                StoreEvent::Ingest | StoreEvent::IngestDuplicate => Level::Info,
                StoreEvent::IngestError
                | StoreEvent::AssertValueFailed
                | StoreEvent::FoundationDBError
                | StoreEvent::MySQLError
                | StoreEvent::PostgreSQLError
                | StoreEvent::RocksDBError
                | StoreEvent::SQLiteError
                | StoreEvent::LdapError
                | StoreEvent::ElasticSearchError
                | StoreEvent::RedisError
                | StoreEvent::S3Error
                | StoreEvent::FilesystemError
                | StoreEvent::PoolError
                | StoreEvent::DataCorruption
                | StoreEvent::DecompressError
                | StoreEvent::DeserializeError
                | StoreEvent::NotConfigured
                | StoreEvent::NotSupported
                | StoreEvent::UnexpectedError
                | StoreEvent::CryptoError => Level::Error,
                StoreEvent::BlobMissingMarker => Level::Warn,
            },
            EventType::Jmap(_) => Level::Debug,
            EventType::Imap(event) => match event {
                ImapEvent::GetAcl
                | ImapEvent::SetAcl
                | ImapEvent::MyRights
                | ImapEvent::ListRights
                | ImapEvent::Append
                | ImapEvent::Capabilities
                | ImapEvent::Id
                | ImapEvent::Close
                | ImapEvent::Copy
                | ImapEvent::Move
                | ImapEvent::CreateMailbox
                | ImapEvent::DeleteMailbox
                | ImapEvent::RenameMailbox
                | ImapEvent::Enable
                | ImapEvent::Expunge
                | ImapEvent::Fetch
                | ImapEvent::List
                | ImapEvent::Lsub
                | ImapEvent::Logout
                | ImapEvent::Namespace
                | ImapEvent::Noop
                | ImapEvent::Search
                | ImapEvent::Sort
                | ImapEvent::Select
                | ImapEvent::Status
                | ImapEvent::Store
                | ImapEvent::Subscribe
                | ImapEvent::Unsubscribe
                | ImapEvent::Thread
                | ImapEvent::Error
                | ImapEvent::IdleStart
                | ImapEvent::IdleStop => Level::Debug,
                ImapEvent::RawInput | ImapEvent::RawOutput => Level::Trace,
            },
            EventType::ManageSieve(event) => match event {
                ManageSieveEvent::CreateScript
                | ManageSieveEvent::UpdateScript
                | ManageSieveEvent::GetScript
                | ManageSieveEvent::DeleteScript
                | ManageSieveEvent::RenameScript
                | ManageSieveEvent::CheckScript
                | ManageSieveEvent::HaveSpace
                | ManageSieveEvent::ListScripts
                | ManageSieveEvent::SetActive
                | ManageSieveEvent::Capabilities
                | ManageSieveEvent::StartTls
                | ManageSieveEvent::Unauthenticate
                | ManageSieveEvent::Logout
                | ManageSieveEvent::Noop
                | ManageSieveEvent::Error => Level::Debug,
                ManageSieveEvent::RawInput | ManageSieveEvent::RawOutput => Level::Trace,
            },
            EventType::Pop3(event) => match event {
                Pop3Event::Delete
                | Pop3Event::Reset
                | Pop3Event::Quit
                | Pop3Event::Fetch
                | Pop3Event::List
                | Pop3Event::ListMessage
                | Pop3Event::Uidl
                | Pop3Event::UidlMessage
                | Pop3Event::Stat
                | Pop3Event::Noop
                | Pop3Event::Capabilities
                | Pop3Event::StartTls
                | Pop3Event::Utf8
                | Pop3Event::Error => Level::Debug,
                Pop3Event::RawInput | Pop3Event::RawOutput => Level::Trace,
            },
            EventType::Smtp(event) => match event {
                SmtpEvent::DidNotSayEhlo
                | SmtpEvent::EhloExpected
                | SmtpEvent::LhloExpected
                | SmtpEvent::MailFromUnauthenticated
                | SmtpEvent::MailFromUnauthorized
                | SmtpEvent::MailFromRewritten
                | SmtpEvent::MailFromMissing
                | SmtpEvent::MultipleMailFrom
                | SmtpEvent::RcptToDuplicate
                | SmtpEvent::RcptToRewritten
                | SmtpEvent::RcptToMissing
                | SmtpEvent::RequireTlsDisabled
                | SmtpEvent::DeliverByDisabled
                | SmtpEvent::DeliverByInvalid
                | SmtpEvent::FutureReleaseDisabled
                | SmtpEvent::FutureReleaseInvalid
                | SmtpEvent::MtPriorityDisabled
                | SmtpEvent::MtPriorityInvalid
                | SmtpEvent::DsnDisabled
                | SmtpEvent::AuthExchangeTooLong
                | SmtpEvent::AlreadyAuthenticated
                | SmtpEvent::Noop
                | SmtpEvent::StartTls
                | SmtpEvent::StartTlsUnavailable
                | SmtpEvent::StartTlsAlready
                | SmtpEvent::Rset
                | SmtpEvent::Quit
                | SmtpEvent::Help
                | SmtpEvent::CommandNotImplemented
                | SmtpEvent::InvalidCommand
                | SmtpEvent::InvalidSenderAddress
                | SmtpEvent::InvalidRecipientAddress
                | SmtpEvent::InvalidParameter
                | SmtpEvent::UnsupportedParameter
                | SmtpEvent::SyntaxError
                | SmtpEvent::PipeSuccess
                | SmtpEvent::PipeError
                | SmtpEvent::Error => Level::Debug,
                SmtpEvent::MissingLocalHostname | SmtpEvent::RemoteIdNotFound => Level::Warn,
                SmtpEvent::ConcurrencyLimitExceeded
                | SmtpEvent::TransferLimitExceeded
                | SmtpEvent::RateLimitExceeded
                | SmtpEvent::TimeLimitExceeded
                | SmtpEvent::MissingAuthDirectory
                | SmtpEvent::MessageParseFailed
                | SmtpEvent::MessageTooLarge
                | SmtpEvent::LoopDetected
                | SmtpEvent::DkimPass
                | SmtpEvent::DkimFail
                | SmtpEvent::ArcPass
                | SmtpEvent::ArcFail
                | SmtpEvent::SpfEhloPass
                | SmtpEvent::SpfEhloFail
                | SmtpEvent::SpfFromPass
                | SmtpEvent::SpfFromFail
                | SmtpEvent::DmarcPass
                | SmtpEvent::DmarcFail
                | SmtpEvent::IprevPass
                | SmtpEvent::IprevFail
                | SmtpEvent::TooManyMessages
                | SmtpEvent::Ehlo
                | SmtpEvent::InvalidEhlo
                | SmtpEvent::MailFrom
                | SmtpEvent::MailboxDoesNotExist
                | SmtpEvent::RelayNotAllowed
                | SmtpEvent::RcptTo
                | SmtpEvent::TooManyInvalidRcpt
                | SmtpEvent::Vrfy
                | SmtpEvent::VrfyNotFound
                | SmtpEvent::VrfyDisabled
                | SmtpEvent::Expn
                | SmtpEvent::ExpnNotFound
                | SmtpEvent::AuthNotAllowed
                | SmtpEvent::AuthMechanismNotSupported
                | SmtpEvent::ExpnDisabled
                | SmtpEvent::RequestTooLarge
                | SmtpEvent::TooManyRecipients => Level::Info,
                SmtpEvent::RawInput | SmtpEvent::RawOutput => Level::Trace,
            },
            EventType::Network(event) => match event {
                NetworkEvent::ReadError
                | NetworkEvent::WriteError
                | NetworkEvent::FlushError
                | NetworkEvent::Closed => Level::Trace,
                NetworkEvent::Timeout | NetworkEvent::AcceptError => Level::Debug,
                NetworkEvent::ConnectionStart
                | NetworkEvent::ConnectionEnd
                | NetworkEvent::ListenStart
                | NetworkEvent::ListenStop
                | NetworkEvent::DropBlocked => Level::Info,
                NetworkEvent::ListenError
                | NetworkEvent::BindError
                | NetworkEvent::SetOptError
                | NetworkEvent::SplitError => Level::Error,
                NetworkEvent::ProxyError => Level::Warn,
            },
            EventType::Limit(cause) => match cause {
                LimitEvent::SizeRequest => Level::Debug,
                LimitEvent::SizeUpload => Level::Debug,
                LimitEvent::CallsIn => Level::Debug,
                LimitEvent::ConcurrentRequest => Level::Debug,
                LimitEvent::ConcurrentUpload => Level::Debug,
                LimitEvent::ConcurrentConnection => Level::Warn,
                LimitEvent::Quota => Level::Debug,
                LimitEvent::BlobQuota => Level::Debug,
                LimitEvent::TooManyRequests => Level::Warn,
            },
            EventType::Manage(_) => Level::Debug,
            EventType::Auth(cause) => match cause {
                AuthEvent::Failed => Level::Debug,
                AuthEvent::MissingTotp => Level::Trace,
                AuthEvent::TooManyAttempts => Level::Warn,
                AuthEvent::Banned => Level::Warn,
                AuthEvent::Error => Level::Error,
                AuthEvent::Success => Level::Info,
            },
            EventType::Config(cause) => match cause {
                ConfigEvent::ParseError
                | ConfigEvent::BuildError
                | ConfigEvent::MacroError
                | ConfigEvent::WriteError
                | ConfigEvent::FetchError => Level::Error,
                ConfigEvent::DefaultApplied
                | ConfigEvent::MissingSetting
                | ConfigEvent::UnusedSetting
                | ConfigEvent::ParseWarning
                | ConfigEvent::BuildWarning
                | ConfigEvent::AlreadyUpToDate
                | ConfigEvent::ExternalKeyIgnored => Level::Debug,
                ConfigEvent::ImportExternal => Level::Info,
            },
            EventType::Resource(cause) => match cause {
                ResourceEvent::NotFound => Level::Debug,
                ResourceEvent::BadParameters | ResourceEvent::Error => Level::Error,
                ResourceEvent::DownloadExternal | ResourceEvent::WebadminUnpacked => Level::Info,
            },
            EventType::Arc(event) => match event {
                ArcEvent::ChainTooLong
                | ArcEvent::InvalidInstance
                | ArcEvent::InvalidCV
                | ArcEvent::HasHeaderTag
                | ArcEvent::BrokenChain => Level::Debug,
                ArcEvent::SealerNotFound => Level::Warn,
            },
            EventType::Dkim(event) => match event {
                DkimEvent::SignerNotFound => Level::Warn,
                _ => Level::Debug,
            },
            EventType::MailAuth(_) => Level::Debug,
            EventType::Purge(event) => match event {
                PurgeEvent::Started => Level::Debug,
                PurgeEvent::Finished => Level::Debug,
                PurgeEvent::Running => Level::Info,
                PurgeEvent::Error => Level::Error,
                PurgeEvent::PurgeActive
                | PurgeEvent::AutoExpunge
                | PurgeEvent::TombstoneCleanup => Level::Debug,
            },
            EventType::Eval(event) => match event {
                EvalEvent::Result => Level::Trace,
                EvalEvent::Error => Level::Error,
                EvalEvent::DirectoryNotFound => Level::Warn,
                EvalEvent::StoreNotFound => Level::Warn,
            },
            EventType::Server(event) => match event {
                ServerEvent::Startup => Level::Info,
                ServerEvent::Shutdown => Level::Info,
                ServerEvent::Licensing => Level::Info,
                ServerEvent::StartupError => Level::Error,
                ServerEvent::ThreadError => Level::Error,
            },
            EventType::Acme(event) => match event {
                AcmeEvent::DnsRecordCreated
                | AcmeEvent::DnsRecordPropagated
                | AcmeEvent::TlsAlpnReceived
                | AcmeEvent::AuthStart
                | AcmeEvent::AuthPending
                | AcmeEvent::AuthValid
                | AcmeEvent::AuthCompleted
                | AcmeEvent::ProcessCert
                | AcmeEvent::OrderProcessing
                | AcmeEvent::OrderReady
                | AcmeEvent::OrderValid
                | AcmeEvent::OrderStart
                | AcmeEvent::OrderCompleted => Level::Info,
                AcmeEvent::Error => Level::Error,
                AcmeEvent::OrderInvalid
                | AcmeEvent::AuthError
                | AcmeEvent::AuthTooManyAttempts
                | AcmeEvent::TokenNotFound
                | AcmeEvent::DnsRecordPropagationTimeout
                | AcmeEvent::TlsAlpnError
                | AcmeEvent::DnsRecordCreationFailed => Level::Warn,
                AcmeEvent::RenewBackoff
                | AcmeEvent::DnsRecordDeletionFailed
                | AcmeEvent::ClientSuppliedSNI
                | AcmeEvent::ClientMissingSNI
                | AcmeEvent::DnsRecordNotPropagated
                | AcmeEvent::DnsRecordLookupFailed => Level::Debug,
            },
            EventType::Tls(event) => match event {
                TlsEvent::Handshake => Level::Info,
                TlsEvent::HandshakeError => Level::Debug,
                TlsEvent::NotConfigured => Level::Error,
                TlsEvent::CertificateNotFound
                | TlsEvent::NoCertificatesAvailable
                | TlsEvent::MultipleCertificatesAvailable => Level::Warn,
            },
            EventType::Sieve(event) => match event {
                SieveEvent::NotSupported
                | SieveEvent::QuotaExceeded
                | SieveEvent::ListNotFound
                | SieveEvent::ScriptNotFound
                | SieveEvent::RuntimeError
                | SieveEvent::MessageTooLarge => Level::Warn,
                SieveEvent::SendMessage => Level::Info,
                SieveEvent::UnexpectedError => Level::Error,
                SieveEvent::ActionAccept
                | SieveEvent::ActionAcceptReplace
                | SieveEvent::ActionDiscard
                | SieveEvent::ActionReject => Level::Debug,
            },
            EventType::Spam(event) => match event {
                SpamEvent::PyzorError | SpamEvent::TrainError | SpamEvent::ClassifyError => {
                    Level::Warn
                }
                SpamEvent::Train
                | SpamEvent::Classify
                | SpamEvent::NotEnoughTrainingData
                | SpamEvent::TrainBalance => Level::Debug,
                SpamEvent::ListUpdated => Level::Info,
            },
            EventType::Http(event) => match event {
                HttpEvent::Error | HttpEvent::XForwardedMissing => Level::Warn,
                HttpEvent::RequestUrl => Level::Debug,
                HttpEvent::RequestBody | HttpEvent::ResponseBody => Level::Trace,
            },
            EventType::PushSubscription(event) => match event {
                PushSubscriptionEvent::Error | PushSubscriptionEvent::NotFound => Level::Debug,
                PushSubscriptionEvent::Success => Level::Trace,
            },
            EventType::Cluster(event) => match event {
                ClusterEvent::PeerAlive
                | ClusterEvent::PeerDiscovered
                | ClusterEvent::PeerOffline
                | ClusterEvent::PeerSuspected
                | ClusterEvent::PeerSuspectedIsAlive
                | ClusterEvent::PeerBackOnline
                | ClusterEvent::PeerLeaving => Level::Info,
                ClusterEvent::PeerHasConfigChanges
                | ClusterEvent::PeerHasListChanges
                | ClusterEvent::OneOrMorePeersOffline => Level::Debug,
                ClusterEvent::EmptyPacket
                | ClusterEvent::Error
                | ClusterEvent::DecryptionError
                | ClusterEvent::InvalidPacket => Level::Warn,
            },
            EventType::Housekeeper(event) => match event {
                HousekeeperEvent::Start
                | HousekeeperEvent::PurgeAccounts
                | HousekeeperEvent::PurgeSessions
                | HousekeeperEvent::PurgeStore
                | HousekeeperEvent::Schedule
                | HousekeeperEvent::Stop => Level::Info,
            },
            EventType::FtsIndex(event) => match event {
                FtsIndexEvent::Index => Level::Info,
                FtsIndexEvent::LockBusy => Level::Warn,
                FtsIndexEvent::BlobNotFound
                | FtsIndexEvent::Locked
                | FtsIndexEvent::MetadataNotFound => Level::Debug,
            },
            EventType::Dmarc(_) => Level::Debug,
            EventType::Spf(_) => Level::Debug,
            EventType::Iprev(_) => Level::Debug,
            EventType::Milter(event) => match event {
                MilterEvent::Read | MilterEvent::Write => Level::Trace,
                MilterEvent::ActionAccept
                | MilterEvent::ActionDiscard
                | MilterEvent::ActionReject
                | MilterEvent::ActionTempFail
                | MilterEvent::ActionReplyCode
                | MilterEvent::ActionConnectionFailure
                | MilterEvent::ActionShutdown => Level::Info,
                MilterEvent::IoError
                | MilterEvent::FrameTooLarge
                | MilterEvent::FrameInvalid
                | MilterEvent::UnexpectedResponse
                | MilterEvent::Timeout
                | MilterEvent::TlsInvalidName
                | MilterEvent::Disconnected
                | MilterEvent::ParseError => Level::Warn,
            },
            EventType::MtaHook(event) => match event {
                MtaHookEvent::ActionAccept
                | MtaHookEvent::ActionDiscard
                | MtaHookEvent::ActionReject
                | MtaHookEvent::ActionQuarantine => Level::Info,
                MtaHookEvent::Error => Level::Warn,
            },
            EventType::Dane(event) => match event {
                DaneEvent::AuthenticationSuccess
                | DaneEvent::AuthenticationFailure
                | DaneEvent::NoCertificatesFound
                | DaneEvent::CertificateParseError
                | DaneEvent::TlsaRecordMatch
                | DaneEvent::TlsaRecordFetch
                | DaneEvent::TlsaRecordFetchError
                | DaneEvent::TlsaRecordNotFound
                | DaneEvent::TlsaRecordNotDnssecSigned
                | DaneEvent::TlsaRecordInvalid => Level::Info,
            },
            EventType::Delivery(event) => match event {
                DeliveryEvent::AttemptStart
                | DeliveryEvent::AttemptEnd
                | DeliveryEvent::Completed
                | DeliveryEvent::Failed
                | DeliveryEvent::AttemptCount
                | DeliveryEvent::MxLookupFailed
                | DeliveryEvent::IpLookupFailed
                | DeliveryEvent::NullMX
                | DeliveryEvent::Connect
                | DeliveryEvent::ConnectError
                | DeliveryEvent::GreetingFailed
                | DeliveryEvent::EhloRejected
                | DeliveryEvent::AuthFailed
                | DeliveryEvent::MailFromRejected
                | DeliveryEvent::Delivered
                | DeliveryEvent::RcptToRejected
                | DeliveryEvent::RcptToFailed
                | DeliveryEvent::MessageRejected
                | DeliveryEvent::StartTls
                | DeliveryEvent::StartTlsUnavailable
                | DeliveryEvent::StartTlsError
                | DeliveryEvent::StartTlsDisabled
                | DeliveryEvent::ImplicitTlsError
                | DeliveryEvent::DoubleBounce => Level::Info,
                DeliveryEvent::ConcurrencyLimitExceeded
                | DeliveryEvent::RateLimitExceeded
                | DeliveryEvent::MissingOutboundHostname => Level::Warn,
                DeliveryEvent::DsnSuccess
                | DeliveryEvent::DsnTempFail
                | DeliveryEvent::DsnPermFail => Level::Info,
                DeliveryEvent::MxLookup
                | DeliveryEvent::IpLookup
                | DeliveryEvent::Ehlo
                | DeliveryEvent::Auth
                | DeliveryEvent::MailFrom
                | DeliveryEvent::RcptTo => Level::Debug,
                DeliveryEvent::RawInput | DeliveryEvent::RawOutput => Level::Trace,
            },
            EventType::Queue(event) => match event {
                QueueEvent::RateLimitExceeded
                | QueueEvent::ConcurrencyLimitExceeded
                | QueueEvent::Scheduled
                | QueueEvent::Rescheduled
                | QueueEvent::QuotaExceeded => Level::Info,
                QueueEvent::LockBusy | QueueEvent::Locked | QueueEvent::BlobNotFound => {
                    Level::Debug
                }
            },
            EventType::TlsRpt(event) => match event {
                TlsRptEvent::RecordFetch | TlsRptEvent::RecordFetchError => Level::Info,
            },
            EventType::MtaSts(event) => match event {
                MtaStsEvent::PolicyFetch
                | MtaStsEvent::PolicyNotFound
                | MtaStsEvent::PolicyFetchError
                | MtaStsEvent::InvalidPolicy
                | MtaStsEvent::NotAuthorized
                | MtaStsEvent::Authorized => Level::Info,
            },
            EventType::IncomingReport(event) => match event {
                IncomingReportEvent::DmarcReportWithWarnings
                | IncomingReportEvent::TlsReportWithWarnings => Level::Warn,
                IncomingReportEvent::DmarcReport
                | IncomingReportEvent::TlsReport
                | IncomingReportEvent::AbuseReport
                | IncomingReportEvent::AuthFailureReport
                | IncomingReportEvent::FraudReport
                | IncomingReportEvent::NotSpamReport
                | IncomingReportEvent::VirusReport
                | IncomingReportEvent::OtherReport
                | IncomingReportEvent::MessageParseFailed
                | IncomingReportEvent::DmarcParseFailed
                | IncomingReportEvent::TlsRpcParseFailed
                | IncomingReportEvent::ArfParseFailed
                | IncomingReportEvent::DecompressError => Level::Info,
            },
            EventType::OutgoingReport(event) => match event {
                OutgoingReportEvent::LockBusy
                | OutgoingReportEvent::LockDeleted
                | OutgoingReportEvent::Locked
                | OutgoingReportEvent::NotFound => Level::Info,
                OutgoingReportEvent::SpfReport
                | OutgoingReportEvent::SpfRateLimited
                | OutgoingReportEvent::DkimReport
                | OutgoingReportEvent::DkimRateLimited
                | OutgoingReportEvent::DmarcReport
                | OutgoingReportEvent::DmarcRateLimited
                | OutgoingReportEvent::DmarcAggregateReport
                | OutgoingReportEvent::TlsAggregate
                | OutgoingReportEvent::HttpSubmission
                | OutgoingReportEvent::UnauthorizedReportingAddress
                | OutgoingReportEvent::ReportingAddressValidationError
                | OutgoingReportEvent::SubmissionError
                | OutgoingReportEvent::NoRecipientsFound => Level::Info,
            },
        }
    }
}
