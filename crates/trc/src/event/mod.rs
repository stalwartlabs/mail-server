/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod conv;
pub mod description;
pub mod level;
pub mod metrics;

use compact_str::ToCompactString;
use std::fmt::Display;

use crate::*;

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

    pub fn into_boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl Error {
    #[inline(always)]
    pub fn new(inner: EventType) -> Self {
        Error(Box::new(Event::new(inner)))
    }

    #[inline(always)]
    pub fn set_ctx(&mut self, key: Key, value: impl Into<Value>) {
        self.0.keys.push((key, value.into()));
    }

    #[inline(always)]
    pub fn ctx(mut self, key: Key, value: impl Into<Value>) -> Self {
        self.0.keys.push((key, value.into()));
        self
    }

    #[inline(always)]
    pub fn ctx_unique(mut self, key: Key, value: impl Into<Value>) -> Self {
        if self.0.keys.iter().all(|(k, _)| *k != key) {
            self.0.keys.push((key, value.into()));
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
        self.0.inner == inner
    }

    #[inline(always)]
    pub fn event_type(&self) -> EventType {
        self.0.inner
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
        self.ctx(Key::Reason, error.to_compact_string())
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
    pub fn keys(&self) -> &[(Key, Value)] {
        &self.0.keys
    }

    #[inline(always)]
    pub fn value(&self, key: Key) -> Option<&Value> {
        self.0.value(key)
    }

    #[inline(always)]
    pub fn value_as_str(&self, key: Key) -> Option<&str> {
        self.0.value_as_str(key)
    }

    #[inline(always)]
    pub fn value_as_uint(&self, key: Key) -> Option<u64> {
        self.0.value_as_uint(key)
    }

    #[inline(always)]
    pub fn take_value(&mut self, key: Key) -> Option<Value> {
        self.0.take_value(key)
    }

    #[inline(always)]
    pub fn is_assertion_failure(&self) -> bool {
        self.0.inner == EventType::Store(StoreEvent::AssertValueFailed)
    }

    pub fn key(&self, key: Key) -> Option<&Value> {
        self.0
            .keys
            .iter()
            .find_map(|(k, v)| if *k == key { Some(v) } else { None })
    }

    #[inline(always)]
    pub fn is_jmap_method_error(&self) -> bool {
        !matches!(
            self.0.inner,
            EventType::Jmap(
                JmapEvent::UnknownCapability | JmapEvent::NotJson | JmapEvent::NotRequest
            )
        )
    }

    #[inline(always)]
    pub fn must_disconnect(&self) -> bool {
        matches!(
            self.0.inner,
            EventType::Network(_)
                | EventType::Auth(AuthEvent::TooManyAttempts)
                | EventType::Limit(LimitEvent::ConcurrentRequest | LimitEvent::TooManyRequests)
                | EventType::Security(_)
        )
    }

    #[inline(always)]
    pub fn should_write_err(&self) -> bool {
        !matches!(self.0.inner, EventType::Network(_) | EventType::Security(_))
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
    pub fn is_span_start(&self) -> bool {
        matches!(
            self,
            EventType::Smtp(SmtpEvent::ConnectionStart)
                | EventType::Imap(ImapEvent::ConnectionStart)
                | EventType::ManageSieve(ManageSieveEvent::ConnectionStart)
                | EventType::Pop3(Pop3Event::ConnectionStart)
                | EventType::Http(HttpEvent::ConnectionStart)
                | EventType::Delivery(DeliveryEvent::AttemptStart)
        )
    }

    #[inline(always)]
    pub fn is_span_end(&self) -> bool {
        matches!(
            self,
            EventType::Smtp(SmtpEvent::ConnectionEnd)
                | EventType::Imap(ImapEvent::ConnectionEnd)
                | EventType::ManageSieve(ManageSieveEvent::ConnectionEnd)
                | EventType::Pop3(Pop3Event::ConnectionEnd)
                | EventType::Http(HttpEvent::ConnectionEnd)
                | EventType::Delivery(DeliveryEvent::AttemptEnd)
        )
    }

    pub fn is_raw_io(&self) -> bool {
        matches!(
            self,
            EventType::Imap(ImapEvent::RawInput | ImapEvent::RawOutput)
                | EventType::Smtp(SmtpEvent::RawInput | SmtpEvent::RawOutput)
                | EventType::Pop3(Pop3Event::RawInput | Pop3Event::RawOutput)
                | EventType::ManageSieve(ManageSieveEvent::RawInput | ManageSieveEvent::RawOutput)
                | EventType::Delivery(DeliveryEvent::RawInput | DeliveryEvent::RawOutput)
                | EventType::Milter(MilterEvent::Read | MilterEvent::Write)
        )
    }

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
            EventType::Security(_) => "Insufficient permissions",
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
            Self::AzureError => "Azure error",
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
            _ => "Store error",
        }
    }
}

impl SecurityEvent {
    #[inline(always)]
    pub fn into_err(self) -> Error {
        Error::new(EventType::Security(self))
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
            Self::TenantQuota => "Tenant quota exceeded",
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
            Self::String(value.into())
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
            _ => None,
        }
    }

    pub fn into_string(self) -> Option<CompactString> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

impl<T> AddContext<T> for Result<T> {
    #[inline(always)]
    fn caused_by(self, location: &'static str) -> Result<T> {
        match self {
            Ok(value) => Ok(value),
            Err(mut err) => {
                err.set_ctx(Key::CausedBy, location);
                Err(err)
            }
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

impl std::error::Error for Error {}
impl Eq for Error {}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        if self.0.inner == other.0.inner && self.0.keys.len() == other.0.keys.len() {
            for kv in self.0.keys.iter() {
                if !other.0.keys.iter().any(|okv| kv == okv) {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::UInt(l0), Self::UInt(r0)) => l0 == r0,
            (Self::Int(l0), Self::Int(r0)) => l0 == r0,
            (Self::Float(l0), Self::Float(r0)) => l0 == r0,
            (Self::Bytes(l0), Self::Bytes(r0)) => l0 == r0,
            (Self::Bool(l0), Self::Bool(r0)) => l0 == r0,
            (Self::Ipv4(l0), Self::Ipv4(r0)) => l0 == r0,
            (Self::Ipv6(l0), Self::Ipv6(r0)) => l0 == r0,
            (Self::Event(l0), Self::Event(r0)) => l0 == r0,
            (Self::Array(l0), Self::Array(r0)) => l0 == r0,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl From<EventType> for usize {
    fn from(value: EventType) -> Self {
        value.id()
    }
}

impl AsRef<Event<EventDetails>> for Event<EventDetails> {
    fn as_ref(&self) -> &Event<EventDetails> {
        self
    }
}
