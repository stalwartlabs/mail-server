/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, cmp::Ordering, fmt::Display, str::FromStr};

use crate::*;

impl Event {
    pub fn new(inner: EventType, level: Level, capacity: usize) -> Self {
        Self {
            inner,
            level,
            keys: Vec::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub fn ctx(mut self, key: Key, value: impl Into<Value>) -> Self {
        self.keys.push((key, value.into()));
        self
    }

    pub fn ctx_opt(self, key: Key, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.ctx(key, value),
            None => self,
        }
    }
}

impl Error {
    pub fn new(inner: EventType) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(5),
        }
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
            Self::Error => "Authentication error",
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

impl Error {
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
}

impl Value {
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
            (Self::Error(l0), Self::Error(r0)) => l0 == r0,
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
                StoreEvent::SqlQuery | StoreEvent::LdapQuery => Level::Trace,
                _ => Level::Error,
            },
            EventType::Jmap(_) => Level::Debug,
            EventType::Imap(event) => match event {
                ImapEvent::Error => Level::Debug,
            },
            EventType::ManageSieve(event) => match event {
                ManageSieveEvent::Error => Level::Debug,
            },
            EventType::Pop3(event) => match event {
                Pop3Event::Error => Level::Debug,
            },
            EventType::Smtp(event) => match event {
                SmtpEvent::Error => Level::Debug,
            },
            EventType::Network(event) => match event {
                NetworkEvent::ReadError
                | NetworkEvent::WriteError
                | NetworkEvent::FlushError
                | NetworkEvent::Closed => Level::Trace,
                NetworkEvent::Timeout => Level::Debug,
            },
            EventType::Limit(cause) => match cause {
                LimitEvent::SizeRequest => Level::Debug,
                LimitEvent::SizeUpload => Level::Debug,
                LimitEvent::CallsIn => Level::Debug,
                LimitEvent::ConcurrentRequest => Level::Debug,
                LimitEvent::ConcurrentUpload => Level::Debug,
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
            },
            EventType::Config(cause) => match cause {
                ConfigEvent::ParseError => Level::Error,
                ConfigEvent::BuildError => Level::Error,
                ConfigEvent::MacroError => Level::Error,
                ConfigEvent::WriteError => Level::Error,
                ConfigEvent::FetchError => Level::Error,
                ConfigEvent::DefaultApplied => Level::Debug,
                ConfigEvent::MissingSetting => Level::Debug,
                ConfigEvent::UnusedSetting => Level::Debug,
                ConfigEvent::ParseWarning => Level::Debug,
                ConfigEvent::BuildWarning => Level::Debug,
            },
            EventType::Resource(cause) => match cause {
                ResourceEvent::NotFound => Level::Debug,
                ResourceEvent::BadParameters => Level::Error,
                ResourceEvent::Error => Level::Error,
            },
            EventType::Arc(_) => Level::Debug,
            EventType::Dkim(_) => Level::Debug,
            EventType::MailAuth(_) => Level::Debug,
            EventType::Purge(event) => match event {
                PurgeEvent::Started => Level::Debug,
                PurgeEvent::Finished => Level::Debug,
                PurgeEvent::Running => Level::Info,
                PurgeEvent::Error => Level::Error,
            },
            EventType::Eval(event) => match event {
                EvalEvent::Result => Level::Trace,
                EvalEvent::Error => Level::Error,
            },
            EventType::Server(event) => match event {
                ServerEvent::Startup => Level::Info,
                ServerEvent::Shutdown => Level::Info,
                ServerEvent::Licensing => Level::Info,
                ServerEvent::StartupError => Level::Error,
                ServerEvent::ThreadError => Level::Error,
            },
            EventType::Acme(event) => match event {
                AcmeEvent::DnsRecordCreated => Level::Info,
                AcmeEvent::DnsRecordNotPropagated => Level::Debug,
                AcmeEvent::DnsRecordLookupFailed => Level::Debug,
                AcmeEvent::DnsRecordPropagated => Level::Info,
                AcmeEvent::DnsRecordPropagationTimeout => Level::Warn,
                AcmeEvent::AuthStart => Level::Info,
                AcmeEvent::AuthPending => Level::Info,
                AcmeEvent::AuthValid => Level::Info,
                AcmeEvent::AuthCompleted => Level::Info,
                AcmeEvent::ProcessCert => Level::Info,
                AcmeEvent::OrderProcessing => Level::Info,
                AcmeEvent::OrderReady => Level::Info,
                AcmeEvent::OrderValid => Level::Info,
                AcmeEvent::OrderInvalid => Level::Warn,
                AcmeEvent::RenewBackoff => Level::Debug,
                AcmeEvent::Error => Level::Error,
                AcmeEvent::AuthError => Level::Warn,
                AcmeEvent::AuthTooManyAttempts => Level::Warn,
                AcmeEvent::DnsRecordCreationFailed => Level::Warn,
                AcmeEvent::DnsRecordDeletionFailed => Level::Debug,
            },
        }
    }
}
