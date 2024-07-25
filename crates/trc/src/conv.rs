/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Debug, time::Duration};

use crate::*;

impl AsRef<EventType> for Error {
    fn as_ref(&self) -> &EventType {
        &self.inner
    }
}

impl From<&'static str> for Value {
    fn from(value: &'static str) -> Self {
        Self::Static(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::UInt(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<u16> for Value {
    fn from(value: u16) -> Self {
        Self::UInt(value.into())
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Int(value.into())
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Self::UInt(value.into())
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::UInt(value as u64)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<IpAddr> for Value {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => Value::Ipv4(ip),
            IpAddr::V6(ip) => Value::Ipv6(Box::new(ip)),
        }
    }
}

impl From<Duration> for Value {
    fn from(value: Duration) -> Self {
        Self::Duration(value.as_millis() as u64)
    }
}

impl From<Event> for Value {
    fn from(value: Event) -> Self {
        Self::Event(Box::new(value))
    }
}

impl From<Level> for Value {
    fn from(value: Level) -> Self {
        Self::Level(value)
    }
}

impl From<EventType> for Error {
    fn from(value: EventType) -> Self {
        Error::new(value)
    }
}

impl From<StoreEvent> for Error {
    fn from(value: StoreEvent) -> Self {
        Error::new(EventType::Store(value))
    }
}

impl From<AuthEvent> for Error {
    fn from(value: AuthEvent) -> Self {
        Error::new(EventType::Auth(value))
    }
}

impl From<Protocol> for Value {
    fn from(value: Protocol) -> Self {
        Self::Protocol(value)
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(value)
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

impl From<Cow<'static, str>> for Value {
    fn from(value: Cow<'static, str>) -> Self {
        match value {
            Cow::Borrowed(value) => Self::Static(value),
            Cow::Owned(value) => Self::String(value),
        }
    }
}

impl<T> From<&crate::Result<T>> for Value
where
    T: Debug,
{
    fn from(value: &crate::Result<T>) -> Self {
        match value {
            Ok(value) => format!("{:?}", value).into(),
            Err(err) => err.clone().into(),
        }
    }
}

impl<T> From<Vec<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Vec<T>) -> Self {
        Self::Array(value.into_iter().map(Into::into).collect())
    }
}

impl<T> From<&[T]> for Value
where
    T: Into<Value> + Clone,
{
    fn from(value: &[T]) -> Self {
        Self::Array(value.iter().map(|v| v.clone().into()).collect())
    }
}

impl EventType {
    pub fn from_io_error(self, err: std::io::Error) -> Error {
        self.reason(err).details("I/O error")
    }

    pub fn from_json_error(self, err: serde_json::Error) -> Error {
        self.reason(err).details("JSON deserialization failed")
    }

    pub fn from_base64_error(self, err: base64::DecodeError) -> Error {
        self.reason(err).details("Base64 decoding failed")
    }

    pub fn from_http_error(self, err: reqwest::Error) -> Error {
        self.into_err()
            .ctx_opt(Key::Url, err.url().map(|url| url.as_ref().to_string()))
            .ctx_opt(Key::Code, err.status().map(|status| status.as_u16()))
            .reason(err)
    }

    pub fn from_bincode_error(self, err: bincode::Error) -> Error {
        self.reason(err).details("Bincode deserialization failed")
    }

    pub fn from_http_str_error(self, err: reqwest::header::ToStrError) -> Error {
        self.reason(err)
            .details("Failed to convert header to string")
    }
}

impl From<mail_auth::Error> for Event {
    fn from(err: mail_auth::Error) -> Self {
        match err {
            mail_auth::Error::ParseError => {
                EventType::MailAuth(MailAuthEvent::ParseError).into_err()
            }
            mail_auth::Error::MissingParameters => {
                EventType::MailAuth(MailAuthEvent::MissingParameters).into_err()
            }
            mail_auth::Error::NoHeadersFound => {
                EventType::MailAuth(MailAuthEvent::NoHeadersFound).into_err()
            }
            mail_auth::Error::CryptoError(details) => EventType::MailAuth(MailAuthEvent::Crypto)
                .into_err()
                .details(details),
            mail_auth::Error::Io(details) => EventType::MailAuth(MailAuthEvent::Io)
                .into_err()
                .details(details),
            mail_auth::Error::Base64 => EventType::MailAuth(MailAuthEvent::Base64).into_err(),
            mail_auth::Error::UnsupportedVersion => {
                EventType::Dkim(DkimEvent::UnsupportedVersion).into_err()
            }
            mail_auth::Error::UnsupportedAlgorithm => {
                EventType::Dkim(DkimEvent::UnsupportedAlgorithm).into_err()
            }
            mail_auth::Error::UnsupportedCanonicalization => {
                EventType::Dkim(DkimEvent::UnsupportedCanonicalization).into_err()
            }
            mail_auth::Error::UnsupportedKeyType => {
                EventType::Dkim(DkimEvent::UnsupportedKeyType).into_err()
            }
            mail_auth::Error::FailedBodyHashMatch => {
                EventType::Dkim(DkimEvent::FailedBodyHashMatch).into_err()
            }
            mail_auth::Error::FailedVerification => {
                EventType::Dkim(DkimEvent::FailedVerification).into_err()
            }
            mail_auth::Error::FailedAuidMatch => {
                EventType::Dkim(DkimEvent::FailedAuidMatch).into_err()
            }
            mail_auth::Error::RevokedPublicKey => {
                EventType::Dkim(DkimEvent::RevokedPublicKey).into_err()
            }
            mail_auth::Error::IncompatibleAlgorithms => {
                EventType::Dkim(DkimEvent::IncompatibleAlgorithms).into_err()
            }
            mail_auth::Error::SignatureExpired => {
                EventType::Dkim(DkimEvent::SignatureExpired).into_err()
            }
            mail_auth::Error::SignatureLength => {
                EventType::Dkim(DkimEvent::SignatureLength).into_err()
            }
            mail_auth::Error::DnsError(details) => EventType::MailAuth(MailAuthEvent::DnsError)
                .into_err()
                .details(details),
            mail_auth::Error::DnsRecordNotFound(code) => {
                EventType::MailAuth(MailAuthEvent::DnsRecordNotFound)
                    .into_err()
                    .code(code.to_str())
            }
            mail_auth::Error::ArcChainTooLong => EventType::Arc(ArcEvent::ChainTooLong).into_err(),
            mail_auth::Error::ArcInvalidInstance(instance) => {
                EventType::Arc(ArcEvent::InvalidInstance).ctx(Key::Id, instance)
            }
            mail_auth::Error::ArcInvalidCV => EventType::Arc(ArcEvent::InvalidCV).into_err(),
            mail_auth::Error::ArcHasHeaderTag => EventType::Arc(ArcEvent::HasHeaderTag).into_err(),
            mail_auth::Error::ArcBrokenChain => EventType::Arc(ArcEvent::BrokenChain).into_err(),
            mail_auth::Error::NotAligned => {
                EventType::MailAuth(MailAuthEvent::PolicyNotAligned).into_err()
            }
            mail_auth::Error::InvalidRecordType => {
                EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType).into_err()
            }
        }
    }
}

impl From<&mail_auth::DkimResult> for Event {
    fn from(value: &mail_auth::DkimResult) -> Self {
        match value.clone() {
            mail_auth::DkimResult::Pass => Event::new(EventType::Dkim(DkimEvent::Pass)),
            mail_auth::DkimResult::Neutral(err) => {
                Event::new(EventType::Dkim(DkimEvent::Neutral)).caused_by(Event::from(err))
            }
            mail_auth::DkimResult::Fail(err) => {
                Event::new(EventType::Dkim(DkimEvent::Fail)).caused_by(Event::from(err))
            }
            mail_auth::DkimResult::PermError(err) => {
                Event::new(EventType::Dkim(DkimEvent::PermError)).caused_by(Event::from(err))
            }
            mail_auth::DkimResult::TempError(err) => {
                Event::new(EventType::Dkim(DkimEvent::TempError)).caused_by(Event::from(err))
            }
            mail_auth::DkimResult::None => Event::new(EventType::Dkim(DkimEvent::None)),
        }
    }
}

impl From<&mail_auth::DmarcResult> for Event {
    fn from(value: &mail_auth::DmarcResult) -> Self {
        match value.clone() {
            mail_auth::DmarcResult::Pass => Event::new(EventType::Dmarc(DmarcEvent::Pass)),
            mail_auth::DmarcResult::Fail(err) => {
                Event::new(EventType::Dmarc(DmarcEvent::Fail)).caused_by(Event::from(err))
            }
            mail_auth::DmarcResult::PermError(err) => {
                Event::new(EventType::Dmarc(DmarcEvent::PermError)).caused_by(Event::from(err))
            }
            mail_auth::DmarcResult::TempError(err) => {
                Event::new(EventType::Dmarc(DmarcEvent::TempError)).caused_by(Event::from(err))
            }
            mail_auth::DmarcResult::None => Event::new(EventType::Dmarc(DmarcEvent::None)),
        }
    }
}

impl From<&mail_auth::DkimOutput<'_>> for Event {
    fn from(value: &mail_auth::DkimOutput<'_>) -> Self {
        Event::from(value.result()).ctx_opt(Key::Contents, value.signature().map(|s| s.to_string()))
    }
}

impl From<&mail_auth::IprevOutput> for Event {
    fn from(value: &mail_auth::IprevOutput) -> Self {
        match value.result().clone() {
            mail_auth::IprevResult::Pass => Event::new(EventType::Iprev(IprevEvent::Pass)),
            mail_auth::IprevResult::Fail(err) => {
                Event::new(EventType::Iprev(IprevEvent::Fail)).caused_by(Event::from(err))
            }
            mail_auth::IprevResult::PermError(err) => {
                Event::new(EventType::Iprev(IprevEvent::PermError)).caused_by(Event::from(err))
            }
            mail_auth::IprevResult::TempError(err) => {
                Event::new(EventType::Iprev(IprevEvent::TempError)).caused_by(Event::from(err))
            }
            mail_auth::IprevResult::None => Event::new(EventType::Iprev(IprevEvent::None)),
        }
        .ctx_opt(
            Key::Details,
            value.ptr.as_ref().map(|s| {
                s.iter()
                    .map(|v| Value::String(v.to_string()))
                    .collect::<Vec<_>>()
            }),
        )
    }
}

impl From<&mail_auth::SpfOutput> for Event {
    fn from(value: &mail_auth::SpfOutput) -> Self {
        Event::new(EventType::Spf(match value.result() {
            mail_auth::SpfResult::Pass => SpfEvent::Pass,
            mail_auth::SpfResult::Fail => SpfEvent::Fail,
            mail_auth::SpfResult::SoftFail => SpfEvent::SoftFail,
            mail_auth::SpfResult::Neutral => SpfEvent::Neutral,
            mail_auth::SpfResult::PermError => SpfEvent::PermError,
            mail_auth::SpfResult::TempError => SpfEvent::TempError,
            mail_auth::SpfResult::None => SpfEvent::None,
        }))
        .ctx_opt(Key::Details, value.explanation().map(|s| s.to_string()))
    }
}

pub trait AssertSuccess
where
    Self: Sized,
{
    fn assert_success(
        self,
        cause: EventType,
    ) -> impl std::future::Future<Output = crate::Result<Self>> + Send;
}

impl AssertSuccess for reqwest::Response {
    async fn assert_success(self, cause: EventType) -> crate::Result<Self> {
        let status = self.status();
        if status.is_success() {
            Ok(self)
        } else {
            Err(cause
                .ctx(Key::Code, status.as_u16())
                .details("HTTP request failed")
                .ctx_opt(Key::Reason, self.text().await.ok()))
        }
    }
}
