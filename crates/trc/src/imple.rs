/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, cmp::Ordering, fmt::Display};

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
    pub fn new(inner: Cause) -> Self {
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

    pub fn ctx_opt(self, key: Key, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(value) => self.ctx(key, value),
            None => self,
        }
    }

    #[inline(always)]
    pub fn matches(&self, inner: Cause) -> bool {
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
        Cause::Store(StoreCause::DataCorruption)
            .ctx(Key::Key, key)
            .ctx_opt(Key::Value, value)
            .ctx(Key::CausedBy, caused_by)
    }
}

impl Cause {
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
            Self::Store(cause) => cause.message(),
            Self::Jmap(cause) => cause.message(),
            Self::Imap => "IMAP error",
            Self::ManageSieve => "ManageSieve error",
            Self::Pop3 => "POP3 error",
            Self::Smtp => "SMTP error",
            Self::Thread => "Thread error",
            Self::Acme => "ACME error",
            Self::Dns => "DNS error",
            Self::Ingest => "Message Ingest error",
            Self::Network => "Network error",
            Self::Limit(cause) => cause.message(),
            Self::Manage(cause) => cause.message(),
            Self::Auth(cause) => cause.message(),
            Self::Configuration => "Configuration error",
            Self::Resource(cause) => cause.message(),
        }
    }
}

impl StoreCause {
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
        Error::new(Cause::Store(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::AssertValue => "Another process has modified the value",
            Self::BlobMissingMarker => "Blob is missing marker",
            Self::FoundationDB => "FoundationDB error",
            Self::MySQL => "MySQL error",
            Self::PostgreSQL => "PostgreSQL error",
            Self::RocksDB => "RocksDB error",
            Self::SQLite => "SQLite error",
            Self::Ldap => "LDAP error",
            Self::ElasticSearch => "ElasticSearch error",
            Self::Redis => "Redis error",
            Self::S3 => "S3 error",
            Self::Filesystem => "Filesystem error",
            Self::Pool => "Connection pool error",
            Self::DataCorruption => "Data corruption",
            Self::Decompress => "Decompression error",
            Self::Deserialize => "Deserialization error",
            Self::NotFound => "Not found",
            Self::NotConfigured => "Not configured",
            Self::NotSupported => "Operation not supported",
            Self::Unexpected => "Unexpected error",
            Self::Crypto => "Crypto error",
        }
    }
}

impl AuthCause {
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
        Error::new(Cause::Auth(self))
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

impl ManageCause {
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
        Error::new(Cause::Manage(self))
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

impl JmapCause {
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
        Error::new(Cause::Jmap(self))
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

impl LimitCause {
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
        Error::new(Cause::Limit(self))
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

impl ResourceCause {
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
        Error::new(Cause::Resource(self))
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::NotFound => "Not found",
            Self::BadParameters => "Bad parameters",
            Self::Error => "Resource error",
        }
    }
}

impl Error {
    #[inline(always)]
    pub fn wrap(self, cause: Cause) -> Self {
        Error::new(cause).caused_by(self)
    }

    #[inline(always)]
    pub fn is_assertion_failure(&self) -> bool {
        self.inner == Cause::Store(StoreCause::AssertValue)
    }

    #[inline(always)]
    pub fn is_jmap_method_error(&self) -> bool {
        !matches!(
            self.inner,
            Cause::Jmap(JmapCause::UnknownCapability | JmapCause::NotJSON | JmapCause::NotRequest)
        )
    }

    #[inline(always)]
    pub fn must_disconnect(&self) -> bool {
        matches!(
            self.inner,
            Cause::Network
                | Cause::Auth(AuthCause::TooManyAttempts | AuthCause::Banned)
                | Cause::Limit(LimitCause::ConcurrentRequest | LimitCause::TooManyRequests)
        )
    }

    #[inline(always)]
    pub fn should_write_err(&self) -> bool {
        !matches!(self.inner, Cause::Network | Cause::Auth(AuthCause::Banned))
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

impl Eq for Error {}

impl EventType {
    pub fn level(&self) -> Level {
        match self {
            EventType::Error(error) => match error {
                Cause::Store(_) => Level::Error,
                Cause::Jmap(_) => Level::Debug,
                Cause::Imap => Level::Debug,
                Cause::ManageSieve => Level::Debug,
                Cause::Pop3 => Level::Debug,
                Cause::Smtp => Level::Debug,
                Cause::Thread => Level::Error,
                Cause::Acme => Level::Error,
                Cause::Dns => Level::Error,
                Cause::Ingest => Level::Error,
                Cause::Network => Level::Debug,
                Cause::Limit(cause) => match cause {
                    LimitCause::SizeRequest => Level::Debug,
                    LimitCause::SizeUpload => Level::Debug,
                    LimitCause::CallsIn => Level::Debug,
                    LimitCause::ConcurrentRequest => Level::Debug,
                    LimitCause::ConcurrentUpload => Level::Debug,
                    LimitCause::Quota => Level::Debug,
                    LimitCause::BlobQuota => Level::Debug,
                    LimitCause::TooManyRequests => Level::Warn,
                },
                Cause::Manage(_) => Level::Debug,
                Cause::Auth(cause) => match cause {
                    AuthCause::Failed => Level::Debug,
                    AuthCause::MissingTotp => Level::Trace,
                    AuthCause::TooManyAttempts => Level::Warn,
                    AuthCause::Banned => Level::Warn,
                    AuthCause::Error => Level::Error,
                },
                Cause::Configuration => Level::Error,
                Cause::Resource(cause) => match cause {
                    ResourceCause::NotFound => Level::Debug,
                    ResourceCause::BadParameters => Level::Error,
                    ResourceCause::Error => Level::Error,
                },
            },
            EventType::NewConnection => Level::Info,
            EventType::SqlQuery => Level::Trace,
            EventType::LdapQuery => Level::Trace,
            EventType::Purge(event) => match event {
                PurgeEvent::Started => Level::Debug,
                PurgeEvent::Finished => Level::Debug,
                PurgeEvent::Running => Level::Info,
                PurgeEvent::Error => Level::Error,
            },
        }
    }
}
