/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{borrow::Cow, cmp::Ordering, fmt::Display, str::FromStr};

impl<T> Event<T> {
    pub fn with_capacity(inner: T, capacity: usize) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(capacity),
        }
    }

    pub fn with_keys(inner: T, keys: Vec<(Key, Value)>) -> Self {
        Self { inner, keys }
    }

    pub fn new(inner: T) -> Self {
        Self {
            inner,
            keys: Vec::with_capacity(5),
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

    pub fn value_as_uint(&self, key: Key) -> Option<u64> {
        self.value(key).and_then(|v| v.to_uint())
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
}

impl Event<EventType> {
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
    pub fn span_id(self, session_id: u64) -> Self {
        self.ctx(Key::SpanId, session_id)
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
                JmapEvent::UnknownCapability | JmapEvent::NotJson | JmapEvent::NotRequest
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

impl Event<EventDetails> {
    pub fn span_id(&self) -> Option<u64> {
        for (key, value) in &self.keys {
            match (key, value) {
                (Key::SpanId, Value::UInt(value)) => return Some(*value),
                (Key::SpanId, Value::Int(value)) => return Some(*value as u64),
                _ => {}
            }
        }

        None
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
            Self::FoundationdbError => "FoundationDB error",
            Self::MysqlError => "MySQL error",
            Self::PostgresqlError => "PostgreSQL error",
            Self::RocksdbError => "RocksDB error",
            Self::SqliteError => "SQLite error",
            Self::LdapError => "LDAP error",
            Self::ElasticsearchError => "ElasticSearch error",
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
            Self::NotJson => "Not JSON",
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

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Static(value) => value.fmt(f),
            Value::String(value) => value.fmt(f),
            Value::UInt(value) => value.fmt(f),
            Value::Int(value) => value.fmt(f),
            Value::Float(value) => value.fmt(f),
            Value::Timestamp(value) => value.fmt(f),
            Value::Duration(value) => value.fmt(f),
            Value::Bytes(value) => STANDARD.encode(value).fmt(f),
            Value::Bool(value) => value.fmt(f),
            Value::Ipv4(value) => value.fmt(f),
            Value::Ipv6(value) => value.fmt(f),
            Value::Protocol(value) => value.name().fmt(f),
            Value::Event(value) => {
                "{".fmt(f)?;
                value.fmt(f)?;
                "}".fmt(f)
            }
            Value::Array(value) => {
                f.write_str("[")?;
                for (i, value) in value.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    value.fmt(f)?;
                }
                f.write_str("]")
            }
            Value::None => "(null)".fmt(f),
        }
    }
}

impl Display for Event<EventType> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.description().fmt(f)?;
        " (".fmt(f)?;
        self.inner.name().fmt(f)?;
        ")".fmt(f)?;

        if !self.keys.is_empty() {
            f.write_str(": ")?;
            for (i, (key, value)) in self.keys.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                key.name().fmt(f)?;
                f.write_str(" = ")?;
                value.fmt(f)?;
            }
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

    pub fn is_contained(&self, other: Self) -> bool {
        *self >= other && other != Level::Disable && *self != Level::Disable
    }
}

impl Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Eq for Error {}

impl EventType {
    #[inline(always)]
    pub fn is_span_start(&self) -> bool {
        matches!(
            self,
            EventType::Network(NetworkEvent::ConnectionStart)
                | EventType::Delivery(DeliveryEvent::AttemptStart)
        )
    }

    #[inline(always)]
    pub fn is_span_end(&self) -> bool {
        matches!(
            self,
            EventType::Network(NetworkEvent::ConnectionEnd)
                | EventType::Delivery(DeliveryEvent::AttemptEnd)
        )
    }

    pub fn description(&self) -> &'static str {
        match self {
            EventType::Store(event) => event.description(),
            EventType::Jmap(event) => event.description(),
            EventType::Imap(event) => event.description(),
            EventType::ManageSieve(event) => event.description(),
            EventType::Pop3(event) => event.description(),
            EventType::Smtp(event) => event.description(),
            EventType::Network(event) => event.description(),
            EventType::Limit(event) => event.description(),
            EventType::Manage(event) => event.description(),
            EventType::Auth(event) => event.description(),
            EventType::Config(event) => event.description(),
            EventType::Resource(event) => event.description(),
            EventType::Sieve(event) => event.description(),
            EventType::Spam(event) => event.description(),
            EventType::Server(event) => event.description(),
            EventType::Purge(event) => event.description(),
            EventType::Eval(event) => event.description(),
            EventType::Acme(event) => event.description(),
            EventType::Http(event) => event.description(),
            EventType::Arc(event) => event.description(),
            EventType::Dkim(event) => event.description(),
            EventType::Dmarc(event) => event.description(),
            EventType::Iprev(event) => event.description(),
            EventType::Dane(event) => event.description(),
            EventType::Spf(event) => event.description(),
            EventType::MailAuth(event) => event.description(),
            EventType::Tls(event) => event.description(),
            EventType::PushSubscription(event) => event.description(),
            EventType::Cluster(event) => event.description(),
            EventType::Housekeeper(event) => event.description(),
            EventType::FtsIndex(event) => event.description(),
            EventType::Milter(event) => event.description(),
            EventType::MtaHook(event) => event.description(),
            EventType::Delivery(event) => event.description(),
            EventType::Queue(event) => event.description(),
            EventType::TlsRpt(event) => event.description(),
            EventType::MtaSts(event) => event.description(),
            EventType::IncomingReport(event) => event.description(),
            EventType::OutgoingReport(event) => event.description(),
            EventType::Tracing(event) => event.description(),
        }
    }

    pub fn level(&self) -> Level {
        match self {
            EventType::Store(event) => match event {
                StoreEvent::SqlQuery | StoreEvent::LdapQuery | StoreEvent::LdapBind => Level::Trace,
                StoreEvent::NotFound => Level::Debug,
                StoreEvent::Ingest | StoreEvent::IngestDuplicate => Level::Info,
                StoreEvent::IngestError
                | StoreEvent::AssertValueFailed
                | StoreEvent::FoundationdbError
                | StoreEvent::MysqlError
                | StoreEvent::PostgresqlError
                | StoreEvent::RocksdbError
                | StoreEvent::SqliteError
                | StoreEvent::LdapError
                | StoreEvent::ElasticsearchError
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
                | ArcEvent::InvalidCv
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
                EvalEvent::Error => Level::Debug,
                EvalEvent::Result => Level::Trace,
                EvalEvent::DirectoryNotFound | EvalEvent::StoreNotFound => Level::Warn,
            },
            EventType::Server(event) => match event {
                ServerEvent::Startup | ServerEvent::Shutdown | ServerEvent::Licensing => {
                    Level::Info
                }
                ServerEvent::StartupError | ServerEvent::ThreadError => Level::Error,
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
                | AcmeEvent::ClientSuppliedSni
                | AcmeEvent::ClientMissingSni
                | AcmeEvent::DnsRecordNotPropagated
                | AcmeEvent::DnsRecordLookupFailed => Level::Debug,
            },
            EventType::Tls(event) => match event {
                TlsEvent::Handshake => Level::Info,
                TlsEvent::HandshakeError | TlsEvent::CertificateNotFound => Level::Debug,
                TlsEvent::NotConfigured => Level::Error,
                TlsEvent::NoCertificatesAvailable | TlsEvent::MultipleCertificatesAvailable => {
                    Level::Warn
                }
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
                HttpEvent::XForwardedMissing => Level::Warn,
                HttpEvent::Error | HttpEvent::RequestUrl => Level::Debug,
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
                | DeliveryEvent::DomainDeliveryStart
                | DeliveryEvent::MxLookupFailed
                | DeliveryEvent::IpLookupFailed
                | DeliveryEvent::NullMx
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
            EventType::Tracing(event) => match event {
                TracingEvent::Update => Level::Disable,
                _ => Level::Warn,
            },
        }
    }
}

impl From<EventType> for usize {
    fn from(value: EventType) -> Self {
        value.id()
    }
}

impl HttpEvent {
    pub fn description(&self) -> &'static str {
        match self {
            HttpEvent::Error => "An HTTP error occurred",
            HttpEvent::RequestUrl => "HTTP request URL",
            HttpEvent::RequestBody => "HTTP request body",
            HttpEvent::ResponseBody => "HTTP response body",
            HttpEvent::XForwardedMissing => "X-Forwarded-For header is missing",
        }
    }
}

impl ClusterEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ClusterEvent::PeerAlive => "A peer is alive",
            ClusterEvent::PeerDiscovered => "A new peer was discovered",
            ClusterEvent::PeerOffline => "A peer went offline",
            ClusterEvent::PeerSuspected => "A peer is suspected to be offline",
            ClusterEvent::PeerSuspectedIsAlive => "A suspected peer is actually alive",
            ClusterEvent::PeerBackOnline => "A peer came back online",
            ClusterEvent::PeerLeaving => "A peer is leaving the cluster",
            ClusterEvent::PeerHasConfigChanges => "A peer has configuration changes",
            ClusterEvent::PeerHasListChanges => "A peer has list changes",
            ClusterEvent::OneOrMorePeersOffline => "One or more peers are offline",
            ClusterEvent::EmptyPacket => "Received an empty gossip packet",
            ClusterEvent::InvalidPacket => "Received an invalid gossip packet",
            ClusterEvent::DecryptionError => "Failed to decrypt a gossip packet",
            ClusterEvent::Error => "A cluster error occurred",
        }
    }
}

impl HousekeeperEvent {
    pub fn description(&self) -> &'static str {
        match self {
            HousekeeperEvent::Start => "Housekeeper process started",
            HousekeeperEvent::Stop => "Housekeeper process stopped",
            HousekeeperEvent::Schedule => "Housekeeper task scheduled",
            HousekeeperEvent::PurgeAccounts => "Purging accounts",
            HousekeeperEvent::PurgeSessions => "Purging sessions",
            HousekeeperEvent::PurgeStore => "Purging store",
        }
    }
}

impl FtsIndexEvent {
    pub fn description(&self) -> &'static str {
        match self {
            FtsIndexEvent::Index => "Full-text search index done",
            FtsIndexEvent::Locked => "Full-text search index is locked",
            FtsIndexEvent::LockBusy => "Full-text search index lock is busy",
            FtsIndexEvent::BlobNotFound => "Blob not found for full-text indexing",
            FtsIndexEvent::MetadataNotFound => "Metadata not found for full-text indexing",
        }
    }
}

impl ImapEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ImapEvent::GetAcl => "IMAP GET ACL command",
            ImapEvent::SetAcl => "IMAP SET ACL command",
            ImapEvent::MyRights => "IMAP MYRIGHTS command",
            ImapEvent::ListRights => "IMAP LISTRIGHTS command",
            ImapEvent::Append => "IMAP APPEND command",
            ImapEvent::Capabilities => "IMAP CAPABILITIES command",
            ImapEvent::Id => "IMAP ID command",
            ImapEvent::Close => "IMAP CLOSE command",
            ImapEvent::Copy => "IMAP COPY command",
            ImapEvent::Move => "IMAP MOVE command",
            ImapEvent::CreateMailbox => "IMAP CREATE mailbox command",
            ImapEvent::DeleteMailbox => "IMAP DELETE mailbox command",
            ImapEvent::RenameMailbox => "IMAP RENAME mailbox command",
            ImapEvent::Enable => "IMAP ENABLE command",
            ImapEvent::Expunge => "IMAP EXPUNGE command",
            ImapEvent::Fetch => "IMAP FETCH command",
            ImapEvent::IdleStart => "IMAP IDLE start",
            ImapEvent::IdleStop => "IMAP IDLE stop",
            ImapEvent::List => "IMAP LIST command",
            ImapEvent::Lsub => "IMAP LSUB command",
            ImapEvent::Logout => "IMAP LOGOUT command",
            ImapEvent::Namespace => "IMAP NAMESPACE command",
            ImapEvent::Noop => "IMAP NOOP command",
            ImapEvent::Search => "IMAP SEARCH command",
            ImapEvent::Sort => "IMAP SORT command",
            ImapEvent::Select => "IMAP SELECT command",
            ImapEvent::Status => "IMAP STATUS command",
            ImapEvent::Store => "IMAP STORE command",
            ImapEvent::Subscribe => "IMAP SUBSCRIBE command",
            ImapEvent::Unsubscribe => "IMAP UNSUBSCRIBE command",
            ImapEvent::Thread => "IMAP THREAD command",
            ImapEvent::Error => "IMAP error occurred",
            ImapEvent::RawInput => "Raw IMAP input received",
            ImapEvent::RawOutput => "Raw IMAP output sent",
        }
    }
}

impl Pop3Event {
    pub fn description(&self) -> &'static str {
        match self {
            Pop3Event::Delete => "POP3 DELETE command",
            Pop3Event::Reset => "POP3 RESET command",
            Pop3Event::Quit => "POP3 QUIT command",
            Pop3Event::Fetch => "POP3 FETCH command",
            Pop3Event::List => "POP3 LIST command",
            Pop3Event::ListMessage => "POP3 LIST specific message command",
            Pop3Event::Uidl => "POP3 UIDL command",
            Pop3Event::UidlMessage => "POP3 UIDL specific message command",
            Pop3Event::Stat => "POP3 STAT command",
            Pop3Event::Noop => "POP3 NOOP command",
            Pop3Event::Capabilities => "POP3 CAPABILITIES command",
            Pop3Event::StartTls => "POP3 STARTTLS command",
            Pop3Event::Utf8 => "POP3 UTF8 command",
            Pop3Event::Error => "POP3 error occurred",
            Pop3Event::RawInput => "Raw POP3 input received",
            Pop3Event::RawOutput => "Raw POP3 output sent",
        }
    }
}

impl ManageSieveEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ManageSieveEvent::CreateScript => "ManageSieve CREATE script command",
            ManageSieveEvent::UpdateScript => "ManageSieve UPDATE script command",
            ManageSieveEvent::GetScript => "ManageSieve GET script command",
            ManageSieveEvent::DeleteScript => "ManageSieve DELETE script command",
            ManageSieveEvent::RenameScript => "ManageSieve RENAME script command",
            ManageSieveEvent::CheckScript => "ManageSieve CHECK script command",
            ManageSieveEvent::HaveSpace => "ManageSieve HAVESPACE command",
            ManageSieveEvent::ListScripts => "ManageSieve LIST scripts command",
            ManageSieveEvent::SetActive => "ManageSieve SET ACTIVE command",
            ManageSieveEvent::Capabilities => "ManageSieve CAPABILITIES command",
            ManageSieveEvent::StartTls => "ManageSieve STARTTLS command",
            ManageSieveEvent::Unauthenticate => "ManageSieve UNAUTHENTICATE command",
            ManageSieveEvent::Logout => "ManageSieve LOGOUT command",
            ManageSieveEvent::Noop => "ManageSieve NOOP command",
            ManageSieveEvent::Error => "ManageSieve error occurred",
            ManageSieveEvent::RawInput => "Raw ManageSieve input received",
            ManageSieveEvent::RawOutput => "Raw ManageSieve output sent",
        }
    }
}

impl SmtpEvent {
    pub fn description(&self) -> &'static str {
        match self {
            SmtpEvent::Error => "SMTP error occurred",
            SmtpEvent::RemoteIdNotFound => "Remote host ID not found",
            SmtpEvent::ConcurrencyLimitExceeded => "Concurrency limit exceeded",
            SmtpEvent::TransferLimitExceeded => "Transfer limit exceeded",
            SmtpEvent::RateLimitExceeded => "Rate limit exceeded",
            SmtpEvent::TimeLimitExceeded => "Time limit exceeded",
            SmtpEvent::MissingAuthDirectory => "Missing auth directory",
            SmtpEvent::MessageParseFailed => "Message parsing failed",
            SmtpEvent::MessageTooLarge => "Message too large",
            SmtpEvent::LoopDetected => "Mail loop detected",
            SmtpEvent::PipeSuccess => "Pipe command succeeded",
            SmtpEvent::PipeError => "Pipe command failed",
            SmtpEvent::DkimPass => "DKIM verification passed",
            SmtpEvent::DkimFail => "DKIM verification failed",
            SmtpEvent::ArcPass => "ARC verification passed",
            SmtpEvent::ArcFail => "ARC verification failed",
            SmtpEvent::SpfEhloPass => "SPF EHLO check passed",
            SmtpEvent::SpfEhloFail => "SPF EHLO check failed",
            SmtpEvent::SpfFromPass => "SPF From check passed",
            SmtpEvent::SpfFromFail => "SPF From check failed",
            SmtpEvent::DmarcPass => "DMARC check passed",
            SmtpEvent::DmarcFail => "DMARC check failed",
            SmtpEvent::IprevPass => "IPREV check passed",
            SmtpEvent::IprevFail => "IPREV check failed",
            SmtpEvent::TooManyMessages => "Too many messages",
            SmtpEvent::Ehlo => "SMTP EHLO command",
            SmtpEvent::InvalidEhlo => "Invalid EHLO command",
            SmtpEvent::DidNotSayEhlo => "Client did not say EHLO",
            SmtpEvent::EhloExpected => "EHLO command expected",
            SmtpEvent::LhloExpected => "LHLO command expected",
            SmtpEvent::MailFromUnauthenticated => "MAIL FROM unauthenticated",
            SmtpEvent::MailFromUnauthorized => "MAIL FROM unauthorized",
            SmtpEvent::MailFromRewritten => "MAIL FROM address rewritten",
            SmtpEvent::MailFromMissing => "MAIL FROM address missing",
            SmtpEvent::MailFrom => "SMTP MAIL FROM command",
            SmtpEvent::MultipleMailFrom => "Multiple MAIL FROM commands",
            SmtpEvent::MailboxDoesNotExist => "Mailbox does not exist",
            SmtpEvent::RelayNotAllowed => "Relay not allowed",
            SmtpEvent::RcptTo => "SMTP RCPT TO command",
            SmtpEvent::RcptToDuplicate => "Duplicate RCPT TO",
            SmtpEvent::RcptToRewritten => "RCPT TO address rewritten",
            SmtpEvent::RcptToMissing => "RCPT TO address missing",
            SmtpEvent::TooManyRecipients => "Too many recipients",
            SmtpEvent::TooManyInvalidRcpt => "Too many invalid recipients",
            SmtpEvent::RawInput => "Raw SMTP input received",
            SmtpEvent::RawOutput => "Raw SMTP output sent",
            SmtpEvent::MissingLocalHostname => "Missing local hostname",
            SmtpEvent::Vrfy => "SMTP VRFY command",
            SmtpEvent::VrfyNotFound => "VRFY address not found",
            SmtpEvent::VrfyDisabled => "VRFY command disabled",
            SmtpEvent::Expn => "SMTP EXPN command",
            SmtpEvent::ExpnNotFound => "EXPN address not found",
            SmtpEvent::ExpnDisabled => "EXPN command disabled",
            SmtpEvent::RequireTlsDisabled => "REQUIRETLS extension disabled",
            SmtpEvent::DeliverByDisabled => "DELIVERBY extension disabled",
            SmtpEvent::DeliverByInvalid => "Invalid DELIVERBY parameter",
            SmtpEvent::FutureReleaseDisabled => "FUTURE RELEASE extension disabled",
            SmtpEvent::FutureReleaseInvalid => "Invalid FUTURE RELEASE parameter",
            SmtpEvent::MtPriorityDisabled => "MT-PRIORITY extension disabled",
            SmtpEvent::MtPriorityInvalid => "Invalid MT-PRIORITY parameter",
            SmtpEvent::DsnDisabled => "DSN extension disabled",
            SmtpEvent::AuthNotAllowed => "Authentication not allowed",
            SmtpEvent::AuthMechanismNotSupported => "Auth mechanism not supported",
            SmtpEvent::AuthExchangeTooLong => "Auth exchange too long",
            SmtpEvent::AlreadyAuthenticated => "Already authenticated",
            SmtpEvent::Noop => "SMTP NOOP command",
            SmtpEvent::StartTls => "SMTP STARTTLS command",
            SmtpEvent::StartTlsUnavailable => "STARTTLS unavailable",
            SmtpEvent::StartTlsAlready => "TLS already active",
            SmtpEvent::Rset => "SMTP RSET command",
            SmtpEvent::Quit => "SMTP QUIT command",
            SmtpEvent::Help => "SMTP HELP command",
            SmtpEvent::CommandNotImplemented => "Command not implemented",
            SmtpEvent::InvalidCommand => "Invalid command",
            SmtpEvent::InvalidSenderAddress => "Invalid sender address",
            SmtpEvent::InvalidRecipientAddress => "Invalid recipient address",
            SmtpEvent::InvalidParameter => "Invalid parameter",
            SmtpEvent::UnsupportedParameter => "Unsupported parameter",
            SmtpEvent::SyntaxError => "Syntax error",
            SmtpEvent::RequestTooLarge => "Request too large",
        }
    }
}

impl DeliveryEvent {
    pub fn description(&self) -> &'static str {
        match self {
            DeliveryEvent::AttemptStart => "Delivery attempt started",
            DeliveryEvent::AttemptEnd => "Delivery attempt ended",
            DeliveryEvent::Completed => "Delivery completed",
            DeliveryEvent::Failed => "Delivery failed",
            DeliveryEvent::DomainDeliveryStart => "New delivery attempt for domain",
            DeliveryEvent::MxLookup => "MX record lookup",
            DeliveryEvent::MxLookupFailed => "MX record lookup failed",
            DeliveryEvent::IpLookup => "IP address lookup",
            DeliveryEvent::IpLookupFailed => "IP address lookup failed",
            DeliveryEvent::NullMx => "Null MX record found",
            DeliveryEvent::Connect => "Connecting to remote server",
            DeliveryEvent::ConnectError => "Connection error",
            DeliveryEvent::MissingOutboundHostname => "Missing outbound hostname in configuration",
            DeliveryEvent::GreetingFailed => "SMTP greeting failed",
            DeliveryEvent::Ehlo => "SMTP EHLO command",
            DeliveryEvent::EhloRejected => "SMTP EHLO rejected",
            DeliveryEvent::Auth => "SMTP authentication",
            DeliveryEvent::AuthFailed => "SMTP authentication failed",
            DeliveryEvent::MailFrom => "SMTP MAIL FROM command",
            DeliveryEvent::MailFromRejected => "SMTP MAIL FROM rejected",
            DeliveryEvent::Delivered => "Message delivered",
            DeliveryEvent::RcptTo => "SMTP RCPT TO command",
            DeliveryEvent::RcptToRejected => "SMTP RCPT TO rejected",
            DeliveryEvent::RcptToFailed => "SMTP RCPT TO failed",
            DeliveryEvent::MessageRejected => "Message rejected by remote server",
            DeliveryEvent::StartTls => "SMTP STARTTLS command",
            DeliveryEvent::StartTlsUnavailable => "STARTTLS unavailable",
            DeliveryEvent::StartTlsError => "STARTTLS error",
            DeliveryEvent::StartTlsDisabled => "STARTTLS disabled",
            DeliveryEvent::ImplicitTlsError => "Implicit TLS error",
            DeliveryEvent::ConcurrencyLimitExceeded => "Concurrency limit exceeded",
            DeliveryEvent::RateLimitExceeded => "Rate limit exceeded",
            DeliveryEvent::DoubleBounce => "Discarding message after double bounce",
            DeliveryEvent::DsnSuccess => "DSN success notification",
            DeliveryEvent::DsnTempFail => "DSN temporary failure notification",
            DeliveryEvent::DsnPermFail => "DSN permanent failure notification",
            DeliveryEvent::RawInput => "Raw SMTP input received",
            DeliveryEvent::RawOutput => "Raw SMTP output sent",
        }
    }
}

impl QueueEvent {
    pub fn description(&self) -> &'static str {
        match self {
            QueueEvent::Scheduled => "Message scheduled for delivery",
            QueueEvent::Rescheduled => "Message rescheduled for delivery",
            QueueEvent::LockBusy => "Queue lock is busy",
            QueueEvent::Locked => "Queue is locked",
            QueueEvent::BlobNotFound => "Message blob not found",
            QueueEvent::RateLimitExceeded => "Rate limit exceeded",
            QueueEvent::ConcurrencyLimitExceeded => "Concurrency limit exceeded",
            QueueEvent::QuotaExceeded => "Quota exceeded",
        }
    }
}

impl IncomingReportEvent {
    pub fn description(&self) -> &'static str {
        match self {
            IncomingReportEvent::DmarcReport => "DMARC report received",
            IncomingReportEvent::DmarcReportWithWarnings => "DMARC report received with warnings",
            IncomingReportEvent::TlsReport => "TLS report received",
            IncomingReportEvent::TlsReportWithWarnings => "TLS report received with warnings",
            IncomingReportEvent::AbuseReport => "Abuse report received",
            IncomingReportEvent::AuthFailureReport => "Authentication failure report received",
            IncomingReportEvent::FraudReport => "Fraud report received",
            IncomingReportEvent::NotSpamReport => "Not spam report received",
            IncomingReportEvent::VirusReport => "Virus report received",
            IncomingReportEvent::OtherReport => "Other type of report received",
            IncomingReportEvent::MessageParseFailed => "Failed to parse incoming report message",
            IncomingReportEvent::DmarcParseFailed => "Failed to parse DMARC report",
            IncomingReportEvent::TlsRpcParseFailed => "Failed to parse TLS RPC report",
            IncomingReportEvent::ArfParseFailed => "Failed to parse ARF report",
            IncomingReportEvent::DecompressError => "Error decompressing report",
        }
    }
}

impl OutgoingReportEvent {
    pub fn description(&self) -> &'static str {
        match self {
            OutgoingReportEvent::SpfReport => "SPF report sent",
            OutgoingReportEvent::SpfRateLimited => "SPF report rate limited",
            OutgoingReportEvent::DkimReport => "DKIM report sent",
            OutgoingReportEvent::DkimRateLimited => "DKIM report rate limited",
            OutgoingReportEvent::DmarcReport => "DMARC report sent",
            OutgoingReportEvent::DmarcRateLimited => "DMARC report rate limited",
            OutgoingReportEvent::DmarcAggregateReport => "DMARC aggregate report sent",
            OutgoingReportEvent::TlsAggregate => "TLS aggregate report sent",
            OutgoingReportEvent::HttpSubmission => "Report submitted via HTTP",
            OutgoingReportEvent::UnauthorizedReportingAddress => "Unauthorized reporting address",
            OutgoingReportEvent::ReportingAddressValidationError => {
                "Error validating reporting address"
            }
            OutgoingReportEvent::NotFound => "Report not found",
            OutgoingReportEvent::SubmissionError => "Error submitting report",
            OutgoingReportEvent::NoRecipientsFound => "No recipients found for report",
            OutgoingReportEvent::LockBusy => "Report lock is busy",
            OutgoingReportEvent::LockDeleted => "Report lock was deleted",
            OutgoingReportEvent::Locked => "Report is locked",
        }
    }
}

impl MtaStsEvent {
    pub fn description(&self) -> &'static str {
        match self {
            MtaStsEvent::Authorized => "Host authorized by MTA-STS policy",
            MtaStsEvent::NotAuthorized => "Host not authorized by MTA-STS policy",
            MtaStsEvent::PolicyFetch => "Fetched MTA-STS policy",
            MtaStsEvent::PolicyNotFound => "MTA-STS policy not found",
            MtaStsEvent::PolicyFetchError => "Error fetching MTA-STS policy",
            MtaStsEvent::InvalidPolicy => "Invalid MTA-STS policy",
        }
    }
}

impl TlsRptEvent {
    pub fn description(&self) -> &'static str {
        match self {
            TlsRptEvent::RecordFetch => "Fetched TLS-RPT record",
            TlsRptEvent::RecordFetchError => "Error fetching TLS-RPT record",
        }
    }
}

impl DaneEvent {
    pub fn description(&self) -> &'static str {
        match self {
            DaneEvent::AuthenticationSuccess => "DANE authentication successful",
            DaneEvent::AuthenticationFailure => "DANE authentication failed",
            DaneEvent::NoCertificatesFound => "No certificates found for DANE",
            DaneEvent::CertificateParseError => "Error parsing certificate for DANE",
            DaneEvent::TlsaRecordMatch => "TLSA record match found",
            DaneEvent::TlsaRecordFetch => "Fetching TLSA record",
            DaneEvent::TlsaRecordFetchError => "Error fetching TLSA record",
            DaneEvent::TlsaRecordNotFound => "TLSA record not found",
            DaneEvent::TlsaRecordNotDnssecSigned => "TLSA record not DNSSEC signed",
            DaneEvent::TlsaRecordInvalid => "Invalid TLSA record",
        }
    }
}

impl MilterEvent {
    pub fn description(&self) -> &'static str {
        match self {
            MilterEvent::Read => "Reading from Milter",
            MilterEvent::Write => "Writing to Milter",
            MilterEvent::ActionAccept => "Milter action: Accept",
            MilterEvent::ActionDiscard => "Milter action: Discard",
            MilterEvent::ActionReject => "Milter action: Reject",
            MilterEvent::ActionTempFail => "Milter action: Temporary failure",
            MilterEvent::ActionReplyCode => "Milter action: Reply code",
            MilterEvent::ActionConnectionFailure => "Milter action: Connection failure",
            MilterEvent::ActionShutdown => "Milter action: Shutdown",
            MilterEvent::IoError => "Milter I/O error",
            MilterEvent::FrameTooLarge => "Milter frame too large",
            MilterEvent::FrameInvalid => "Invalid Milter frame",
            MilterEvent::UnexpectedResponse => "Unexpected Milter response",
            MilterEvent::Timeout => "Milter timeout",
            MilterEvent::TlsInvalidName => "Invalid TLS name for Milter",
            MilterEvent::Disconnected => "Milter disconnected",
            MilterEvent::ParseError => "Milter parse error",
        }
    }
}

impl MtaHookEvent {
    pub fn description(&self) -> &'static str {
        match self {
            MtaHookEvent::ActionAccept => "MTA hook action: Accept",
            MtaHookEvent::ActionDiscard => "MTA hook action: Discard",
            MtaHookEvent::ActionReject => "MTA hook action: Reject",
            MtaHookEvent::ActionQuarantine => "MTA hook action: Quarantine",
            MtaHookEvent::Error => "MTA hook error",
        }
    }
}

impl PushSubscriptionEvent {
    pub fn description(&self) -> &'static str {
        match self {
            PushSubscriptionEvent::Success => "Push subscription successful",
            PushSubscriptionEvent::Error => "Push subscription error",
            PushSubscriptionEvent::NotFound => "Push subscription not found",
        }
    }
}

impl SpamEvent {
    pub fn description(&self) -> &'static str {
        match self {
            SpamEvent::PyzorError => "Pyzor error",
            SpamEvent::ListUpdated => "Spam list updated",
            SpamEvent::Train => "Training spam filter",
            SpamEvent::TrainBalance => "Balancing spam filter training data",
            SpamEvent::TrainError => "Error training spam filter",
            SpamEvent::Classify => "Classifying message for spam",
            SpamEvent::ClassifyError => "Error classifying message for spam",
            SpamEvent::NotEnoughTrainingData => "Not enough training data for spam filter",
        }
    }
}

impl SieveEvent {
    pub fn description(&self) -> &'static str {
        match self {
            SieveEvent::ActionAccept => "Sieve action: Accept",
            SieveEvent::ActionAcceptReplace => "Sieve action: Accept and replace",
            SieveEvent::ActionDiscard => "Sieve action: Discard",
            SieveEvent::ActionReject => "Sieve action: Reject",
            SieveEvent::SendMessage => "Sieve sending message",
            SieveEvent::MessageTooLarge => "Sieve message too large",
            SieveEvent::ScriptNotFound => "Sieve script not found",
            SieveEvent::ListNotFound => "Sieve list not found",
            SieveEvent::RuntimeError => "Sieve runtime error",
            SieveEvent::UnexpectedError => "Unexpected Sieve error",
            SieveEvent::NotSupported => "Sieve action not supported",
            SieveEvent::QuotaExceeded => "Sieve quota exceeded",
        }
    }
}

impl TlsEvent {
    pub fn description(&self) -> &'static str {
        match self {
            TlsEvent::Handshake => "TLS handshake",
            TlsEvent::HandshakeError => "TLS handshake error",
            TlsEvent::NotConfigured => "TLS not configured",
            TlsEvent::CertificateNotFound => "TLS certificate not found",
            TlsEvent::NoCertificatesAvailable => "No TLS certificates available",
            TlsEvent::MultipleCertificatesAvailable => "Multiple TLS certificates available",
        }
    }
}

impl NetworkEvent {
    pub fn description(&self) -> &'static str {
        match self {
            NetworkEvent::ConnectionStart => "Network connection started",
            NetworkEvent::ConnectionEnd => "Network connection ended",
            NetworkEvent::ListenStart => "Network listener started",
            NetworkEvent::ListenStop => "Network listener stopped",
            NetworkEvent::ListenError => "Network listener error",
            NetworkEvent::BindError => "Network bind error",
            NetworkEvent::ReadError => "Network read error",
            NetworkEvent::WriteError => "Network write error",
            NetworkEvent::FlushError => "Network flush error",
            NetworkEvent::AcceptError => "Network accept error",
            NetworkEvent::SplitError => "Network split error",
            NetworkEvent::Timeout => "Network timeout",
            NetworkEvent::Closed => "Network connection closed",
            NetworkEvent::ProxyError => "Proxy protocol error",
            NetworkEvent::SetOptError => "Network set option error",
            NetworkEvent::DropBlocked => "Dropped connection from blocked IP address",
        }
    }
}

impl ServerEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ServerEvent::Startup => {
                concat!("Starting Stalwart Mail Server v", env!("CARGO_PKG_VERSION"))
            }
            ServerEvent::Shutdown => concat!(
                "Shutting down Stalwart Mail Server v",
                env!("CARGO_PKG_VERSION")
            ),
            ServerEvent::StartupError => "Server startup error",
            ServerEvent::ThreadError => "Server thread error",
            ServerEvent::Licensing => "Server licensing event",
        }
    }
}

impl TracingEvent {
    pub fn description(&self) -> &'static str {
        match self {
            TracingEvent::Update => "Tracing update",
            TracingEvent::LogError => "Log collector error",
            TracingEvent::WebhookError => "Webhook collector error",
            TracingEvent::OtelError => "OpenTelemetry collector error",
            TracingEvent::JournalError => "Journal collector error",
        }
    }
}

impl AcmeEvent {
    pub fn description(&self) -> &'static str {
        match self {
            AcmeEvent::AuthStart => "ACME authentication started",
            AcmeEvent::AuthPending => "ACME authentication pending",
            AcmeEvent::AuthValid => "ACME authentication valid",
            AcmeEvent::AuthCompleted => "ACME authentication completed",
            AcmeEvent::AuthError => "ACME authentication error",
            AcmeEvent::AuthTooManyAttempts => "Too many ACME authentication attempts",
            AcmeEvent::ProcessCert => "Processing ACME certificate",
            AcmeEvent::OrderStart => "ACME order started",
            AcmeEvent::OrderProcessing => "ACME order processing",
            AcmeEvent::OrderCompleted => "ACME order completed",
            AcmeEvent::OrderReady => "ACME order ready",
            AcmeEvent::OrderValid => "ACME order valid",
            AcmeEvent::OrderInvalid => "ACME order invalid",
            AcmeEvent::RenewBackoff => "ACME renew backoff",
            AcmeEvent::DnsRecordCreated => "ACME DNS record created",
            AcmeEvent::DnsRecordCreationFailed => "ACME DNS record creation failed",
            AcmeEvent::DnsRecordDeletionFailed => "ACME DNS record deletion failed",
            AcmeEvent::DnsRecordNotPropagated => "ACME DNS record not propagated",
            AcmeEvent::DnsRecordLookupFailed => "ACME DNS record lookup failed",
            AcmeEvent::DnsRecordPropagated => "ACME DNS record propagated",
            AcmeEvent::DnsRecordPropagationTimeout => "ACME DNS record propagation timeout",
            AcmeEvent::ClientSuppliedSni => "ACME client supplied SNI",
            AcmeEvent::ClientMissingSni => "ACME client missing SNI",
            AcmeEvent::TlsAlpnReceived => "ACME TLS ALPN received",
            AcmeEvent::TlsAlpnError => "ACME TLS ALPN error",
            AcmeEvent::TokenNotFound => "ACME token not found",
            AcmeEvent::Error => "ACME error",
        }
    }
}

impl PurgeEvent {
    pub fn description(&self) -> &'static str {
        match self {
            PurgeEvent::Started => "Purge started",
            PurgeEvent::Finished => "Purge finished",
            PurgeEvent::Running => "Purge running",
            PurgeEvent::Error => "Purge error",
            PurgeEvent::PurgeActive => "Active purge in progress",
            PurgeEvent::AutoExpunge => "Auto-expunge executed",
            PurgeEvent::TombstoneCleanup => "Tombstone cleanup executed",
        }
    }
}

impl EvalEvent {
    pub fn description(&self) -> &'static str {
        match self {
            EvalEvent::Result => "Expression evaluation result",
            EvalEvent::Error => "Expression evaluation error",
            EvalEvent::DirectoryNotFound => "Directory not found while evaluating expression",
            EvalEvent::StoreNotFound => "Store not found while evaluating expression",
        }
    }
}

impl ConfigEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ConfigEvent::ParseError => "Configuration parse error",
            ConfigEvent::BuildError => "Configuration build error",
            ConfigEvent::MacroError => "Configuration macro error",
            ConfigEvent::WriteError => "Configuration write error",
            ConfigEvent::FetchError => "Configuration fetch error",
            ConfigEvent::DefaultApplied => "Default configuration applied",
            ConfigEvent::MissingSetting => "Missing configuration setting",
            ConfigEvent::UnusedSetting => "Unused configuration setting",
            ConfigEvent::ParseWarning => "Configuration parse warning",
            ConfigEvent::BuildWarning => "Configuration build warning",
            ConfigEvent::ImportExternal => "Importing external configuration",
            ConfigEvent::ExternalKeyIgnored => "External configuration key ignored",
            ConfigEvent::AlreadyUpToDate => "Configuration already up to date",
        }
    }
}

impl ArcEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ArcEvent::ChainTooLong => "ARC chain too long",
            ArcEvent::InvalidInstance => "Invalid ARC instance",
            ArcEvent::InvalidCv => "Invalid ARC CV",
            ArcEvent::HasHeaderTag => "ARC has header tag",
            ArcEvent::BrokenChain => "Broken ARC chain",
            ArcEvent::SealerNotFound => "ARC sealer not found",
        }
    }
}

impl DkimEvent {
    pub fn description(&self) -> &'static str {
        match self {
            DkimEvent::Pass => "DKIM verification passed",
            DkimEvent::Neutral => "DKIM verification neutral",
            DkimEvent::Fail => "DKIM verification failed",
            DkimEvent::PermError => "DKIM permanent error",
            DkimEvent::TempError => "DKIM temporary error",
            DkimEvent::None => "No DKIM signature",
            DkimEvent::UnsupportedVersion => "Unsupported DKIM version",
            DkimEvent::UnsupportedAlgorithm => "Unsupported DKIM algorithm",
            DkimEvent::UnsupportedCanonicalization => "Unsupported DKIM canonicalization",
            DkimEvent::UnsupportedKeyType => "Unsupported DKIM key type",
            DkimEvent::FailedBodyHashMatch => "DKIM body hash mismatch",
            DkimEvent::FailedVerification => "DKIM verification failed",
            DkimEvent::FailedAuidMatch => "DKIM AUID mismatch",
            DkimEvent::RevokedPublicKey => "DKIM public key revoked",
            DkimEvent::IncompatibleAlgorithms => "Incompatible DKIM algorithms",
            DkimEvent::SignatureExpired => "DKIM signature expired",
            DkimEvent::SignatureLength => "DKIM signature length issue",
            DkimEvent::SignerNotFound => "DKIM signer not found",
        }
    }
}

impl SpfEvent {
    pub fn description(&self) -> &'static str {
        match self {
            SpfEvent::Pass => "SPF check passed",
            SpfEvent::Fail => "SPF check failed",
            SpfEvent::SoftFail => "SPF soft fail",
            SpfEvent::Neutral => "SPF neutral result",
            SpfEvent::TempError => "SPF temporary error",
            SpfEvent::PermError => "SPF permanent error",
            SpfEvent::None => "No SPF record",
        }
    }
}

impl DmarcEvent {
    pub fn description(&self) -> &'static str {
        match self {
            DmarcEvent::Pass => "DMARC check passed",
            DmarcEvent::Fail => "DMARC check failed",
            DmarcEvent::PermError => "DMARC permanent error",
            DmarcEvent::TempError => "DMARC temporary error",
            DmarcEvent::None => "No DMARC record",
        }
    }
}

impl IprevEvent {
    pub fn description(&self) -> &'static str {
        match self {
            IprevEvent::Pass => "IPREV check passed",
            IprevEvent::Fail => "IPREV check failed",
            IprevEvent::PermError => "IPREV permanent error",
            IprevEvent::TempError => "IPREV temporary error",
            IprevEvent::None => "No IPREV record",
        }
    }
}

impl MailAuthEvent {
    pub fn description(&self) -> &'static str {
        match self {
            MailAuthEvent::ParseError => "Mail authentication parse error",
            MailAuthEvent::MissingParameters => "Missing mail authentication parameters",
            MailAuthEvent::NoHeadersFound => "No headers found in message",
            MailAuthEvent::Crypto => "Crypto error during mail authentication",
            MailAuthEvent::Io => "I/O error during mail authentication",
            MailAuthEvent::Base64 => "Base64 error during mail authentication",
            MailAuthEvent::DnsError => "DNS error",
            MailAuthEvent::DnsRecordNotFound => "DNS record not found",
            MailAuthEvent::DnsInvalidRecordType => "Invalid DNS record type",
            MailAuthEvent::PolicyNotAligned => "Policy not aligned",
        }
    }
}

impl StoreEvent {
    pub fn description(&self) -> &'static str {
        match self {
            StoreEvent::IngestError => "Message ingestion error",
            StoreEvent::AssertValueFailed => "Another process modified the record",
            StoreEvent::FoundationdbError => "FoundationDB error",
            StoreEvent::MysqlError => "MySQL error",
            StoreEvent::PostgresqlError => "PostgreSQL error",
            StoreEvent::RocksdbError => "RocksDB error",
            StoreEvent::SqliteError => "SQLite error",
            StoreEvent::LdapError => "LDAP error",
            StoreEvent::ElasticsearchError => "ElasticSearch error",
            StoreEvent::RedisError => "Redis error",
            StoreEvent::S3Error => "S3 error",
            StoreEvent::FilesystemError => "Filesystem error",
            StoreEvent::PoolError => "Connection pool error",
            StoreEvent::DataCorruption => "Data corruption detected",
            StoreEvent::DecompressError => "Decompression error",
            StoreEvent::DeserializeError => "Deserialization error",
            StoreEvent::NotFound => "Record not found in database",
            StoreEvent::NotConfigured => "Store not configured",
            StoreEvent::NotSupported => "Operation not supported by store",
            StoreEvent::UnexpectedError => "Unexpected store error",
            StoreEvent::CryptoError => "Store crypto error",
            StoreEvent::BlobMissingMarker => "Blob missing marker",
            StoreEvent::Ingest => "Message ingested",
            StoreEvent::IngestDuplicate => "Skipping duplicate message",
            StoreEvent::SqlQuery => "SQL query executed",
            StoreEvent::LdapQuery => "LDAP query executed",
            StoreEvent::LdapBind => "LDAP bind operation",
        }
    }
}

impl JmapEvent {
    pub fn description(&self) -> &'static str {
        match self {
            JmapEvent::MethodCall => "JMAP method call",
            JmapEvent::InvalidArguments => "Invalid JMAP arguments",
            JmapEvent::RequestTooLarge => "JMAP request too large",
            JmapEvent::StateMismatch => "JMAP state mismatch",
            JmapEvent::AnchorNotFound => "JMAP anchor not found",
            JmapEvent::UnsupportedFilter => "Unsupported JMAP filter",
            JmapEvent::UnsupportedSort => "Unsupported JMAP sort",
            JmapEvent::UnknownMethod => "Unknown JMAP method",
            JmapEvent::InvalidResultReference => "Invalid JMAP result reference",
            JmapEvent::Forbidden => "JMAP operation forbidden",
            JmapEvent::AccountNotFound => "JMAP account not found",
            JmapEvent::AccountNotSupportedByMethod => "JMAP account not supported by method",
            JmapEvent::AccountReadOnly => "JMAP account is read-only",
            JmapEvent::NotFound => "JMAP resource not found",
            JmapEvent::CannotCalculateChanges => "Cannot calculate JMAP changes",
            JmapEvent::UnknownDataType => "Unknown JMAP data type",
            JmapEvent::UnknownCapability => "Unknown JMAP capability",
            JmapEvent::NotJson => "JMAP request is not JSON",
            JmapEvent::NotRequest => "JMAP input is not a request",
            JmapEvent::WebsocketStart => "JMAP WebSocket connection started",
            JmapEvent::WebsocketStop => "JMAP WebSocket connection stopped",
            JmapEvent::WebsocketError => "JMAP WebSocket error",
        }
    }
}

impl LimitEvent {
    pub fn description(&self) -> &'static str {
        match self {
            LimitEvent::SizeRequest => "Request size limit reached",
            LimitEvent::SizeUpload => "Upload size limit reached",
            LimitEvent::CallsIn => "Incoming calls limit reached",
            LimitEvent::ConcurrentRequest => "Concurrent request limit reached",
            LimitEvent::ConcurrentUpload => "Concurrent upload limit reached",
            LimitEvent::ConcurrentConnection => "Concurrent connection limit reached",
            LimitEvent::Quota => "Quota limit reached",
            LimitEvent::BlobQuota => "Blob quota limit reached",
            LimitEvent::TooManyRequests => "Too many requests",
        }
    }
}

impl ManageEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ManageEvent::MissingParameter => "Missing management parameter",
            ManageEvent::AlreadyExists => "Managed resource already exists",
            ManageEvent::AssertFailed => "Management assertion failed",
            ManageEvent::NotFound => "Managed resource not found",
            ManageEvent::NotSupported => "Management operation not supported",
            ManageEvent::Error => "Management error",
        }
    }
}

impl AuthEvent {
    pub fn description(&self) -> &'static str {
        match self {
            AuthEvent::Success => "Authentication successful",
            AuthEvent::Failed => "Authentication failed",
            AuthEvent::MissingTotp => "Missing TOTP for authentication",
            AuthEvent::TooManyAttempts => "Too many authentication attempts",
            AuthEvent::Banned => "IP address banned after multiple authentication failures",
            AuthEvent::Error => "Authentication error",
        }
    }
}

impl ResourceEvent {
    pub fn description(&self) -> &'static str {
        match self {
            ResourceEvent::NotFound => "Resource not found",
            ResourceEvent::BadParameters => "Bad resource parameters",
            ResourceEvent::Error => "Resource error",
            ResourceEvent::DownloadExternal => "Downloading external resource",
            ResourceEvent::WebadminUnpacked => "Webadmin resource unpacked",
        }
    }
}
