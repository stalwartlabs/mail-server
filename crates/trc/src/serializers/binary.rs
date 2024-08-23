/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::*;

const VERSION: u8 = 1;

pub fn serialize_events<'x>(
    events: impl IntoIterator<Item = &'x Event<EventDetails>>,
    num_events: usize,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(num_events * 64);
    buf.push(VERSION);
    leb128_write(&mut buf, num_events as u64);
    for event in events {
        event.serialize(&mut buf);
    }
    buf
}

pub fn deserialize_events(bytes: &[u8]) -> crate::Result<Vec<Event<EventDetails>>> {
    let mut iter = bytes.iter();
    if *iter.next().ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while reading version")
    })? != VERSION
    {
        crate::bail!(StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("Invalid version"));
    }
    let len = leb128_read(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while size")
    })? as usize;
    let mut events = Vec::with_capacity(len);
    for n in 0..len {
        events.push(Event::deserialize(&mut iter).ok_or_else(|| {
            StoreEvent::DataCorruption
                .caused_by(crate::location!())
                .details(format!("Failed to deserialize event {n}"))
        })?);
    }
    Ok(events)
}

pub fn deserialize_single_event(bytes: &[u8]) -> crate::Result<Event<EventDetails>> {
    let mut iter = bytes.iter();
    if *iter.next().ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while reading version")
    })? != VERSION
    {
        crate::bail!(StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("Invalid version"));
    }
    let _ = leb128_read(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("EOF while size")
    })?;
    Event::deserialize(&mut iter).ok_or_else(|| {
        StoreEvent::DataCorruption
            .caused_by(crate::location!())
            .details("Failed to deserialize event")
    })
}

impl Event<EventDetails> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        leb128_write(buf, self.inner.typ.code());
        buf.extend_from_slice(self.inner.timestamp.to_le_bytes().as_ref());
        leb128_write(buf, self.keys.len() as u64);
        for (k, v) in &self.keys {
            leb128_write(buf, k.code());
            v.serialize(buf);
        }
    }
    pub fn deserialize<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        let typ = EventType::from_code(leb128_read(iter)?)?;
        let timestamp = u64::from_le_bytes([
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
        ]);
        let keys_len = leb128_read(iter)?;
        let mut keys = Vec::with_capacity(keys_len as usize);
        for _ in 0..keys_len {
            let key = Key::from_code(leb128_read(iter)?)?;
            let value = Value::deserialize(iter)?;
            keys.push((key, value));
        }
        Some(Event {
            inner: EventDetails {
                typ,
                timestamp,
                level: Level::Info,
                span: None,
            },
            keys,
        })
    }
}

impl Value {
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Value::Static(v) => {
                buf.push(0u8);
                leb128_write(buf, v.len() as u64);
                buf.extend(v.as_bytes());
            }
            Value::String(v) => {
                buf.push(0u8);
                leb128_write(buf, v.len() as u64);
                buf.extend(v.as_bytes());
            }
            Value::UInt(v) => {
                buf.push(1u8);
                leb128_write(buf, *v);
            }
            Value::Int(v) => {
                buf.push(2u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Float(v) => {
                buf.push(3u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Timestamp(v) => {
                buf.push(4u8);
                buf.extend(&v.to_le_bytes());
            }
            Value::Duration(v) => {
                buf.push(5u8);
                leb128_write(buf, *v);
            }
            Value::Bytes(v) => {
                buf.push(6u8);
                leb128_write(buf, v.len() as u64);
                buf.extend(v);
            }
            Value::Bool(true) => {
                buf.push(7u8);
            }
            Value::Bool(false) => {
                buf.push(8u8);
            }
            Value::Ipv4(v) => {
                buf.push(9u8);
                buf.extend(&v.octets());
            }
            Value::Ipv6(v) => {
                buf.push(10u8);
                buf.extend(&v.octets());
            }
            Value::Event(v) => {
                buf.push(11u8);
                leb128_write(buf, v.inner.code());
                leb128_write(buf, v.keys.len() as u64);
                for (k, v) in &v.keys {
                    leb128_write(buf, k.code());
                    v.serialize(buf);
                }
            }
            Value::Array(v) => {
                buf.push(12u8);
                leb128_write(buf, v.len() as u64);
                for value in v {
                    value.serialize(buf);
                }
            }
            Value::None => {
                buf.push(13u8);
            }
        }
    }

    fn deserialize<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<Self> {
        match iter.next()? {
            0 => {
                let mut buf = vec![0u8; leb128_read(iter)? as usize];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::String(String::from_utf8(buf).ok()?))
            }
            1 => Some(Value::UInt(leb128_read(iter)?)),
            2 => {
                let mut buf = [0u8; std::mem::size_of::<i64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Int(i64::from_le_bytes(buf)))
            }
            3 => {
                let mut buf = [0u8; std::mem::size_of::<f64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Float(f64::from_le_bytes(buf)))
            }
            4 => {
                let mut buf = [0u8; std::mem::size_of::<u64>()];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Timestamp(u64::from_le_bytes(buf)))
            }
            5 => Some(Value::Duration(leb128_read(iter)?)),
            6 => {
                let mut buf = vec![0u8; leb128_read(iter)? as usize];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Bytes(buf))
            }
            7 => Some(Value::Bool(true)),
            8 => Some(Value::Bool(false)),
            9 => {
                let mut buf = [0u8; 4];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Ipv4(Ipv4Addr::from(buf)))
            }
            10 => {
                let mut buf = [0u8; 16];
                for byte in buf.iter_mut() {
                    *byte = *iter.next()?;
                }
                Some(Value::Ipv6(Ipv6Addr::from(buf)))
            }
            11 => {
                let code = EventType::from_code(leb128_read(iter)?)?;
                let keys_len = leb128_read(iter)?;
                let mut keys = Vec::with_capacity(keys_len as usize);
                for _ in 0..keys_len {
                    let key = Key::from_code(leb128_read(iter)?)?;
                    let value = Value::deserialize(iter)?;
                    keys.push((key, value));
                }
                Some(Value::Event(Event::with_keys(code, keys)))
            }
            12 => {
                let len = leb128_read(iter)?;
                let mut values = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    values.push(Value::deserialize(iter)?);
                }
                Some(Value::Array(values))
            }
            13 => Some(Value::None),
            _ => None,
        }
    }
}

fn leb128_write(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        if value < 0x80 {
            buf.push(value as u8);
            break;
        } else {
            buf.push(((value & 0x7f) | 0x80) as u8);
            value >>= 7;
        }
    }
}

fn leb128_read<'x>(iter: &mut impl Iterator<Item = &'x u8>) -> Option<u64> {
    let mut result = 0;

    for shift in [0, 7, 14, 21, 28, 35, 42, 49, 56, 63] {
        let byte = iter.next()?;

        if (byte & 0x80) == 0 {
            result |= (*byte as u64) << shift;
            return Some(result);
        } else {
            result |= ((byte & 0x7F) as u64) << shift;
        }
    }

    None
}

impl EventType {
    pub fn code(&self) -> u64 {
        match self {
            EventType::Acme(AcmeEvent::AuthCompleted) => 0,
            EventType::Acme(AcmeEvent::AuthError) => 1,
            EventType::Acme(AcmeEvent::AuthPending) => 2,
            EventType::Acme(AcmeEvent::AuthStart) => 3,
            EventType::Acme(AcmeEvent::AuthTooManyAttempts) => 4,
            EventType::Acme(AcmeEvent::AuthValid) => 5,
            EventType::Acme(AcmeEvent::ClientMissingSni) => 6,
            EventType::Acme(AcmeEvent::ClientSuppliedSni) => 7,
            EventType::Acme(AcmeEvent::DnsRecordCreated) => 8,
            EventType::Acme(AcmeEvent::DnsRecordCreationFailed) => 9,
            EventType::Acme(AcmeEvent::DnsRecordDeletionFailed) => 10,
            EventType::Acme(AcmeEvent::DnsRecordLookupFailed) => 11,
            EventType::Acme(AcmeEvent::DnsRecordNotPropagated) => 12,
            EventType::Acme(AcmeEvent::DnsRecordPropagated) => 13,
            EventType::Acme(AcmeEvent::DnsRecordPropagationTimeout) => 14,
            EventType::Acme(AcmeEvent::Error) => 15,
            EventType::Acme(AcmeEvent::OrderCompleted) => 16,
            EventType::Acme(AcmeEvent::OrderInvalid) => 17,
            EventType::Acme(AcmeEvent::OrderProcessing) => 18,
            EventType::Acme(AcmeEvent::OrderReady) => 19,
            EventType::Acme(AcmeEvent::OrderStart) => 20,
            EventType::Acme(AcmeEvent::OrderValid) => 21,
            EventType::Acme(AcmeEvent::ProcessCert) => 22,
            EventType::Acme(AcmeEvent::RenewBackoff) => 23,
            EventType::Acme(AcmeEvent::TlsAlpnError) => 24,
            EventType::Acme(AcmeEvent::TlsAlpnReceived) => 25,
            EventType::Acme(AcmeEvent::TokenNotFound) => 26,
            EventType::Arc(ArcEvent::BrokenChain) => 27,
            EventType::Arc(ArcEvent::ChainTooLong) => 28,
            EventType::Arc(ArcEvent::HasHeaderTag) => 29,
            EventType::Arc(ArcEvent::InvalidCv) => 30,
            EventType::Arc(ArcEvent::InvalidInstance) => 31,
            EventType::Arc(ArcEvent::SealerNotFound) => 32,
            EventType::Auth(AuthEvent::Banned) => 33,
            EventType::Auth(AuthEvent::Error) => 34,
            EventType::Auth(AuthEvent::Failed) => 35,
            EventType::Auth(AuthEvent::MissingTotp) => 36,
            EventType::Auth(AuthEvent::Success) => 37,
            EventType::Auth(AuthEvent::TooManyAttempts) => 38,
            EventType::Cluster(ClusterEvent::DecryptionError) => 39,
            EventType::Cluster(ClusterEvent::EmptyPacket) => 40,
            EventType::Cluster(ClusterEvent::Error) => 41,
            EventType::Cluster(ClusterEvent::InvalidPacket) => 42,
            EventType::Cluster(ClusterEvent::OneOrMorePeersOffline) => 43,
            EventType::Cluster(ClusterEvent::PeerAlive) => 44,
            EventType::Cluster(ClusterEvent::PeerBackOnline) => 45,
            EventType::Cluster(ClusterEvent::PeerDiscovered) => 46,
            EventType::Cluster(ClusterEvent::PeerHasConfigChanges) => 47,
            EventType::Cluster(ClusterEvent::PeerHasListChanges) => 48,
            EventType::Cluster(ClusterEvent::PeerLeaving) => 49,
            EventType::Cluster(ClusterEvent::PeerOffline) => 50,
            EventType::Cluster(ClusterEvent::PeerSuspected) => 51,
            EventType::Cluster(ClusterEvent::PeerSuspectedIsAlive) => 52,
            EventType::Config(ConfigEvent::AlreadyUpToDate) => 53,
            EventType::Config(ConfigEvent::BuildError) => 54,
            EventType::Config(ConfigEvent::BuildWarning) => 55,
            EventType::Config(ConfigEvent::DefaultApplied) => 56,
            EventType::Config(ConfigEvent::ExternalKeyIgnored) => 57,
            EventType::Config(ConfigEvent::FetchError) => 58,
            EventType::Config(ConfigEvent::ImportExternal) => 59,
            EventType::Config(ConfigEvent::MacroError) => 60,
            EventType::Config(ConfigEvent::MissingSetting) => 61,
            EventType::Config(ConfigEvent::ParseError) => 62,
            EventType::Config(ConfigEvent::ParseWarning) => 63,
            EventType::Config(ConfigEvent::UnusedSetting) => 64,
            EventType::Config(ConfigEvent::WriteError) => 65,
            EventType::Dane(DaneEvent::AuthenticationFailure) => 66,
            EventType::Dane(DaneEvent::AuthenticationSuccess) => 67,
            EventType::Dane(DaneEvent::CertificateParseError) => 68,
            EventType::Dane(DaneEvent::NoCertificatesFound) => 69,
            EventType::Dane(DaneEvent::TlsaRecordFetch) => 70,
            EventType::Dane(DaneEvent::TlsaRecordFetchError) => 71,
            EventType::Dane(DaneEvent::TlsaRecordInvalid) => 72,
            EventType::Dane(DaneEvent::TlsaRecordMatch) => 73,
            EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned) => 74,
            EventType::Dane(DaneEvent::TlsaRecordNotFound) => 75,
            EventType::Delivery(DeliveryEvent::AttemptEnd) => 76,
            EventType::Delivery(DeliveryEvent::AttemptStart) => 77,
            EventType::Delivery(DeliveryEvent::Auth) => 78,
            EventType::Delivery(DeliveryEvent::AuthFailed) => 79,
            EventType::Delivery(DeliveryEvent::Completed) => 80,
            EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded) => 81,
            EventType::Delivery(DeliveryEvent::Connect) => 82,
            EventType::Delivery(DeliveryEvent::ConnectError) => 83,
            EventType::Delivery(DeliveryEvent::Delivered) => 84,
            EventType::Delivery(DeliveryEvent::DomainDeliveryStart) => 85,
            EventType::Delivery(DeliveryEvent::DoubleBounce) => 86,
            EventType::Delivery(DeliveryEvent::DsnPermFail) => 87,
            EventType::Delivery(DeliveryEvent::DsnSuccess) => 88,
            EventType::Delivery(DeliveryEvent::DsnTempFail) => 89,
            EventType::Delivery(DeliveryEvent::Ehlo) => 90,
            EventType::Delivery(DeliveryEvent::EhloRejected) => 91,
            EventType::Delivery(DeliveryEvent::Failed) => 92,
            EventType::Delivery(DeliveryEvent::GreetingFailed) => 93,
            EventType::Delivery(DeliveryEvent::ImplicitTlsError) => 94,
            EventType::Delivery(DeliveryEvent::IpLookup) => 95,
            EventType::Delivery(DeliveryEvent::IpLookupFailed) => 96,
            EventType::Delivery(DeliveryEvent::MailFrom) => 97,
            EventType::Delivery(DeliveryEvent::MailFromRejected) => 98,
            EventType::Delivery(DeliveryEvent::MessageRejected) => 99,
            EventType::Delivery(DeliveryEvent::MissingOutboundHostname) => 100,
            EventType::Delivery(DeliveryEvent::MxLookup) => 101,
            EventType::Delivery(DeliveryEvent::MxLookupFailed) => 102,
            EventType::Delivery(DeliveryEvent::NullMx) => 103,
            EventType::Delivery(DeliveryEvent::RateLimitExceeded) => 104,
            EventType::Delivery(DeliveryEvent::RawInput) => 105,
            EventType::Delivery(DeliveryEvent::RawOutput) => 106,
            EventType::Delivery(DeliveryEvent::RcptTo) => 107,
            EventType::Delivery(DeliveryEvent::RcptToFailed) => 108,
            EventType::Delivery(DeliveryEvent::RcptToRejected) => 109,
            EventType::Delivery(DeliveryEvent::StartTls) => 110,
            EventType::Delivery(DeliveryEvent::StartTlsDisabled) => 111,
            EventType::Delivery(DeliveryEvent::StartTlsError) => 112,
            EventType::Delivery(DeliveryEvent::StartTlsUnavailable) => 113,
            EventType::Dkim(DkimEvent::Fail) => 114,
            EventType::Dkim(DkimEvent::FailedAuidMatch) => 115,
            EventType::Dkim(DkimEvent::FailedBodyHashMatch) => 116,
            EventType::Dkim(DkimEvent::FailedVerification) => 117,
            EventType::Dkim(DkimEvent::IncompatibleAlgorithms) => 118,
            EventType::Dkim(DkimEvent::Neutral) => 119,
            EventType::Dkim(DkimEvent::None) => 120,
            EventType::Dkim(DkimEvent::Pass) => 121,
            EventType::Dkim(DkimEvent::PermError) => 122,
            EventType::Dkim(DkimEvent::RevokedPublicKey) => 123,
            EventType::Dkim(DkimEvent::SignatureExpired) => 124,
            EventType::Dkim(DkimEvent::SignatureLength) => 125,
            EventType::Dkim(DkimEvent::SignerNotFound) => 126,
            EventType::Dkim(DkimEvent::TempError) => 127,
            EventType::Dkim(DkimEvent::UnsupportedAlgorithm) => 128,
            EventType::Dkim(DkimEvent::UnsupportedCanonicalization) => 129,
            EventType::Dkim(DkimEvent::UnsupportedKeyType) => 130,
            EventType::Dkim(DkimEvent::UnsupportedVersion) => 131,
            EventType::Dmarc(DmarcEvent::Fail) => 132,
            EventType::Dmarc(DmarcEvent::None) => 133,
            EventType::Dmarc(DmarcEvent::Pass) => 134,
            EventType::Dmarc(DmarcEvent::PermError) => 135,
            EventType::Dmarc(DmarcEvent::TempError) => 136,
            EventType::Eval(EvalEvent::DirectoryNotFound) => 137,
            EventType::Eval(EvalEvent::Error) => 138,
            EventType::Eval(EvalEvent::Result) => 139,
            EventType::Eval(EvalEvent::StoreNotFound) => 140,
            EventType::FtsIndex(FtsIndexEvent::BlobNotFound) => 141,
            EventType::FtsIndex(FtsIndexEvent::Index) => 142,
            EventType::FtsIndex(FtsIndexEvent::LockBusy) => 143,
            EventType::FtsIndex(FtsIndexEvent::Locked) => 144,
            EventType::FtsIndex(FtsIndexEvent::MetadataNotFound) => 145,
            EventType::Housekeeper(HousekeeperEvent::PurgeAccounts) => 146,
            EventType::Housekeeper(HousekeeperEvent::PurgeSessions) => 147,
            EventType::Housekeeper(HousekeeperEvent::PurgeStore) => 148,
            EventType::Housekeeper(HousekeeperEvent::Schedule) => 149,
            EventType::Housekeeper(HousekeeperEvent::Start) => 150,
            EventType::Housekeeper(HousekeeperEvent::Stop) => 151,
            EventType::Http(HttpEvent::ConnectionEnd) => 152,
            EventType::Http(HttpEvent::ConnectionStart) => 153,
            EventType::Http(HttpEvent::Error) => 154,
            EventType::Http(HttpEvent::RequestBody) => 155,
            EventType::Http(HttpEvent::RequestUrl) => 156,
            EventType::Http(HttpEvent::ResponseBody) => 157,
            EventType::Http(HttpEvent::XForwardedMissing) => 158,
            EventType::Imap(ImapEvent::Append) => 159,
            EventType::Imap(ImapEvent::Capabilities) => 160,
            EventType::Imap(ImapEvent::Close) => 161,
            EventType::Imap(ImapEvent::ConnectionEnd) => 162,
            EventType::Imap(ImapEvent::ConnectionStart) => 163,
            EventType::Imap(ImapEvent::Copy) => 164,
            EventType::Imap(ImapEvent::CreateMailbox) => 165,
            EventType::Imap(ImapEvent::DeleteMailbox) => 166,
            EventType::Imap(ImapEvent::Enable) => 167,
            EventType::Imap(ImapEvent::Error) => 168,
            EventType::Imap(ImapEvent::Expunge) => 169,
            EventType::Imap(ImapEvent::Fetch) => 170,
            EventType::Imap(ImapEvent::GetAcl) => 171,
            EventType::Imap(ImapEvent::Id) => 172,
            EventType::Imap(ImapEvent::IdleStart) => 173,
            EventType::Imap(ImapEvent::IdleStop) => 174,
            EventType::Imap(ImapEvent::List) => 175,
            EventType::Imap(ImapEvent::ListRights) => 176,
            EventType::Imap(ImapEvent::Logout) => 177,
            EventType::Imap(ImapEvent::Lsub) => 178,
            EventType::Imap(ImapEvent::Move) => 179,
            EventType::Imap(ImapEvent::MyRights) => 180,
            EventType::Imap(ImapEvent::Namespace) => 181,
            EventType::Imap(ImapEvent::Noop) => 182,
            EventType::Imap(ImapEvent::RawInput) => 183,
            EventType::Imap(ImapEvent::RawOutput) => 184,
            EventType::Imap(ImapEvent::RenameMailbox) => 185,
            EventType::Imap(ImapEvent::Search) => 186,
            EventType::Imap(ImapEvent::Select) => 187,
            EventType::Imap(ImapEvent::SetAcl) => 188,
            EventType::Imap(ImapEvent::Sort) => 189,
            EventType::Imap(ImapEvent::Status) => 190,
            EventType::Imap(ImapEvent::Store) => 191,
            EventType::Imap(ImapEvent::Subscribe) => 192,
            EventType::Imap(ImapEvent::Thread) => 193,
            EventType::Imap(ImapEvent::Unsubscribe) => 194,
            EventType::IncomingReport(IncomingReportEvent::AbuseReport) => 195,
            EventType::IncomingReport(IncomingReportEvent::ArfParseFailed) => 196,
            EventType::IncomingReport(IncomingReportEvent::AuthFailureReport) => 197,
            EventType::IncomingReport(IncomingReportEvent::DecompressError) => 198,
            EventType::IncomingReport(IncomingReportEvent::DmarcParseFailed) => 199,
            EventType::IncomingReport(IncomingReportEvent::DmarcReport) => 200,
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings) => 201,
            EventType::IncomingReport(IncomingReportEvent::FraudReport) => 202,
            EventType::IncomingReport(IncomingReportEvent::MessageParseFailed) => 203,
            EventType::IncomingReport(IncomingReportEvent::NotSpamReport) => 204,
            EventType::IncomingReport(IncomingReportEvent::OtherReport) => 205,
            EventType::IncomingReport(IncomingReportEvent::TlsReport) => 206,
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings) => 207,
            EventType::IncomingReport(IncomingReportEvent::TlsRpcParseFailed) => 208,
            EventType::IncomingReport(IncomingReportEvent::VirusReport) => 209,
            EventType::Iprev(IprevEvent::Fail) => 210,
            EventType::Iprev(IprevEvent::None) => 211,
            EventType::Iprev(IprevEvent::Pass) => 212,
            EventType::Iprev(IprevEvent::PermError) => 213,
            EventType::Iprev(IprevEvent::TempError) => 214,
            EventType::Jmap(JmapEvent::AccountNotFound) => 215,
            EventType::Jmap(JmapEvent::AccountNotSupportedByMethod) => 216,
            EventType::Jmap(JmapEvent::AccountReadOnly) => 217,
            EventType::Jmap(JmapEvent::AnchorNotFound) => 218,
            EventType::Jmap(JmapEvent::CannotCalculateChanges) => 219,
            EventType::Jmap(JmapEvent::Forbidden) => 220,
            EventType::Jmap(JmapEvent::InvalidArguments) => 221,
            EventType::Jmap(JmapEvent::InvalidResultReference) => 222,
            EventType::Jmap(JmapEvent::MethodCall) => 223,
            EventType::Jmap(JmapEvent::NotFound) => 224,
            EventType::Jmap(JmapEvent::NotJson) => 225,
            EventType::Jmap(JmapEvent::NotRequest) => 226,
            EventType::Jmap(JmapEvent::RequestTooLarge) => 227,
            EventType::Jmap(JmapEvent::StateMismatch) => 228,
            EventType::Jmap(JmapEvent::UnknownCapability) => 229,
            EventType::Jmap(JmapEvent::UnknownDataType) => 230,
            EventType::Jmap(JmapEvent::UnknownMethod) => 231,
            EventType::Jmap(JmapEvent::UnsupportedFilter) => 232,
            EventType::Jmap(JmapEvent::UnsupportedSort) => 233,
            EventType::Jmap(JmapEvent::WebsocketError) => 234,
            EventType::Jmap(JmapEvent::WebsocketStart) => 235,
            EventType::Jmap(JmapEvent::WebsocketStop) => 236,
            EventType::Limit(LimitEvent::BlobQuota) => 237,
            EventType::Limit(LimitEvent::CallsIn) => 238,
            EventType::Limit(LimitEvent::ConcurrentConnection) => 239,
            EventType::Limit(LimitEvent::ConcurrentRequest) => 240,
            EventType::Limit(LimitEvent::ConcurrentUpload) => 241,
            EventType::Limit(LimitEvent::Quota) => 242,
            EventType::Limit(LimitEvent::SizeRequest) => 243,
            EventType::Limit(LimitEvent::SizeUpload) => 244,
            EventType::Limit(LimitEvent::TooManyRequests) => 245,
            EventType::MailAuth(MailAuthEvent::Base64) => 246,
            EventType::MailAuth(MailAuthEvent::Crypto) => 247,
            EventType::MailAuth(MailAuthEvent::DnsError) => 248,
            EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType) => 249,
            EventType::MailAuth(MailAuthEvent::DnsRecordNotFound) => 250,
            EventType::MailAuth(MailAuthEvent::Io) => 251,
            EventType::MailAuth(MailAuthEvent::MissingParameters) => 252,
            EventType::MailAuth(MailAuthEvent::NoHeadersFound) => 253,
            EventType::MailAuth(MailAuthEvent::ParseError) => 254,
            EventType::MailAuth(MailAuthEvent::PolicyNotAligned) => 255,
            EventType::ManageSieve(ManageSieveEvent::Capabilities) => 256,
            EventType::ManageSieve(ManageSieveEvent::CheckScript) => 257,
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => 258,
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => 259,
            EventType::ManageSieve(ManageSieveEvent::CreateScript) => 260,
            EventType::ManageSieve(ManageSieveEvent::DeleteScript) => 261,
            EventType::ManageSieve(ManageSieveEvent::Error) => 262,
            EventType::ManageSieve(ManageSieveEvent::GetScript) => 263,
            EventType::ManageSieve(ManageSieveEvent::HaveSpace) => 264,
            EventType::ManageSieve(ManageSieveEvent::ListScripts) => 265,
            EventType::ManageSieve(ManageSieveEvent::Logout) => 266,
            EventType::ManageSieve(ManageSieveEvent::Noop) => 267,
            EventType::ManageSieve(ManageSieveEvent::RawInput) => 268,
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => 269,
            EventType::ManageSieve(ManageSieveEvent::RenameScript) => 270,
            EventType::ManageSieve(ManageSieveEvent::SetActive) => 271,
            EventType::ManageSieve(ManageSieveEvent::StartTls) => 272,
            EventType::ManageSieve(ManageSieveEvent::Unauthenticate) => 273,
            EventType::ManageSieve(ManageSieveEvent::UpdateScript) => 274,
            EventType::Manage(ManageEvent::AlreadyExists) => 275,
            EventType::Manage(ManageEvent::AssertFailed) => 276,
            EventType::Manage(ManageEvent::Error) => 277,
            EventType::Manage(ManageEvent::MissingParameter) => 278,
            EventType::Manage(ManageEvent::NotFound) => 279,
            EventType::Manage(ManageEvent::NotSupported) => 280,
            EventType::MessageIngest(MessageIngestEvent::Duplicate) => 281,
            EventType::MessageIngest(MessageIngestEvent::Error) => 282,
            EventType::MessageIngest(MessageIngestEvent::Ham) => 283,
            EventType::MessageIngest(MessageIngestEvent::ImapAppend) => 284,
            EventType::MessageIngest(MessageIngestEvent::JmapAppend) => 285,
            EventType::MessageIngest(MessageIngestEvent::Spam) => 286,
            EventType::Milter(MilterEvent::ActionAccept) => 287,
            EventType::Milter(MilterEvent::ActionConnectionFailure) => 288,
            EventType::Milter(MilterEvent::ActionDiscard) => 289,
            EventType::Milter(MilterEvent::ActionReject) => 290,
            EventType::Milter(MilterEvent::ActionReplyCode) => 291,
            EventType::Milter(MilterEvent::ActionShutdown) => 292,
            EventType::Milter(MilterEvent::ActionTempFail) => 293,
            EventType::Milter(MilterEvent::Disconnected) => 294,
            EventType::Milter(MilterEvent::FrameInvalid) => 295,
            EventType::Milter(MilterEvent::FrameTooLarge) => 296,
            EventType::Milter(MilterEvent::IoError) => 297,
            EventType::Milter(MilterEvent::ParseError) => 298,
            EventType::Milter(MilterEvent::Read) => 299,
            EventType::Milter(MilterEvent::Timeout) => 300,
            EventType::Milter(MilterEvent::TlsInvalidName) => 301,
            EventType::Milter(MilterEvent::UnexpectedResponse) => 302,
            EventType::Milter(MilterEvent::Write) => 303,
            EventType::MtaHook(MtaHookEvent::ActionAccept) => 304,
            EventType::MtaHook(MtaHookEvent::ActionDiscard) => 305,
            EventType::MtaHook(MtaHookEvent::ActionQuarantine) => 306,
            EventType::MtaHook(MtaHookEvent::ActionReject) => 307,
            EventType::MtaHook(MtaHookEvent::Error) => 308,
            EventType::MtaSts(MtaStsEvent::Authorized) => 309,
            EventType::MtaSts(MtaStsEvent::InvalidPolicy) => 310,
            EventType::MtaSts(MtaStsEvent::NotAuthorized) => 311,
            EventType::MtaSts(MtaStsEvent::PolicyFetch) => 312,
            EventType::MtaSts(MtaStsEvent::PolicyFetchError) => 313,
            EventType::MtaSts(MtaStsEvent::PolicyNotFound) => 314,
            EventType::Network(NetworkEvent::AcceptError) => 315,
            EventType::Network(NetworkEvent::BindError) => 316,
            EventType::Network(NetworkEvent::Closed) => 317,
            EventType::Network(NetworkEvent::DropBlocked) => 318,
            EventType::Network(NetworkEvent::FlushError) => 319,
            EventType::Network(NetworkEvent::ListenError) => 320,
            EventType::Network(NetworkEvent::ListenStart) => 321,
            EventType::Network(NetworkEvent::ListenStop) => 322,
            EventType::Network(NetworkEvent::ProxyError) => 323,
            EventType::Network(NetworkEvent::ReadError) => 324,
            EventType::Network(NetworkEvent::SetOptError) => 325,
            EventType::Network(NetworkEvent::SplitError) => 326,
            EventType::Network(NetworkEvent::Timeout) => 327,
            EventType::Network(NetworkEvent::WriteError) => 328,
            EventType::OutgoingReport(OutgoingReportEvent::DkimRateLimited) => 329,
            EventType::OutgoingReport(OutgoingReportEvent::DkimReport) => 330,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcAggregateReport) => 331,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcRateLimited) => 332,
            EventType::OutgoingReport(OutgoingReportEvent::DmarcReport) => 333,
            EventType::OutgoingReport(OutgoingReportEvent::HttpSubmission) => 334,
            EventType::OutgoingReport(OutgoingReportEvent::LockBusy) => 335,
            EventType::OutgoingReport(OutgoingReportEvent::LockDeleted) => 336,
            EventType::OutgoingReport(OutgoingReportEvent::Locked) => 337,
            EventType::OutgoingReport(OutgoingReportEvent::NoRecipientsFound) => 338,
            EventType::OutgoingReport(OutgoingReportEvent::NotFound) => 339,
            EventType::OutgoingReport(OutgoingReportEvent::ReportingAddressValidationError) => 340,
            EventType::OutgoingReport(OutgoingReportEvent::SpfRateLimited) => 341,
            EventType::OutgoingReport(OutgoingReportEvent::SpfReport) => 342,
            EventType::OutgoingReport(OutgoingReportEvent::SubmissionError) => 343,
            EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate) => 344,
            EventType::OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress) => 345,
            EventType::Pop3(Pop3Event::Capabilities) => 346,
            EventType::Pop3(Pop3Event::ConnectionEnd) => 347,
            EventType::Pop3(Pop3Event::ConnectionStart) => 348,
            EventType::Pop3(Pop3Event::Delete) => 349,
            EventType::Pop3(Pop3Event::Error) => 350,
            EventType::Pop3(Pop3Event::Fetch) => 351,
            EventType::Pop3(Pop3Event::List) => 352,
            EventType::Pop3(Pop3Event::ListMessage) => 353,
            EventType::Pop3(Pop3Event::Noop) => 354,
            EventType::Pop3(Pop3Event::Quit) => 355,
            EventType::Pop3(Pop3Event::RawInput) => 356,
            EventType::Pop3(Pop3Event::RawOutput) => 357,
            EventType::Pop3(Pop3Event::Reset) => 358,
            EventType::Pop3(Pop3Event::StartTls) => 359,
            EventType::Pop3(Pop3Event::Stat) => 360,
            EventType::Pop3(Pop3Event::Uidl) => 361,
            EventType::Pop3(Pop3Event::UidlMessage) => 362,
            EventType::Pop3(Pop3Event::Utf8) => 363,
            EventType::Purge(PurgeEvent::AutoExpunge) => 364,
            EventType::Purge(PurgeEvent::Error) => 365,
            EventType::Purge(PurgeEvent::Finished) => 366,
            EventType::Purge(PurgeEvent::PurgeActive) => 367,
            EventType::Purge(PurgeEvent::Running) => 368,
            EventType::Purge(PurgeEvent::Started) => 369,
            EventType::Purge(PurgeEvent::TombstoneCleanup) => 370,
            EventType::PushSubscription(PushSubscriptionEvent::Error) => 371,
            EventType::PushSubscription(PushSubscriptionEvent::NotFound) => 372,
            EventType::PushSubscription(PushSubscriptionEvent::Success) => 373,
            EventType::Queue(QueueEvent::BlobNotFound) => 374,
            EventType::Queue(QueueEvent::ConcurrencyLimitExceeded) => 375,
            EventType::Queue(QueueEvent::LockBusy) => 376,
            EventType::Queue(QueueEvent::Locked) => 377,
            EventType::Queue(QueueEvent::QueueAutogenerated) => 378,
            EventType::Queue(QueueEvent::QueueDsn) => 379,
            EventType::Queue(QueueEvent::QueueMessage) => 380,
            EventType::Queue(QueueEvent::QueueMessageAuthenticated) => 381,
            EventType::Queue(QueueEvent::QueueReport) => 382,
            EventType::Queue(QueueEvent::QuotaExceeded) => 383,
            EventType::Queue(QueueEvent::RateLimitExceeded) => 384,
            EventType::Queue(QueueEvent::Rescheduled) => 385,
            EventType::Resource(ResourceEvent::BadParameters) => 386,
            EventType::Resource(ResourceEvent::DownloadExternal) => 387,
            EventType::Resource(ResourceEvent::Error) => 388,
            EventType::Resource(ResourceEvent::NotFound) => 389,
            EventType::Resource(ResourceEvent::WebadminUnpacked) => 390,
            EventType::Server(ServerEvent::Licensing) => 391,
            EventType::Server(ServerEvent::Shutdown) => 392,
            EventType::Server(ServerEvent::Startup) => 393,
            EventType::Server(ServerEvent::StartupError) => 394,
            EventType::Server(ServerEvent::ThreadError) => 395,
            EventType::Sieve(SieveEvent::ActionAccept) => 396,
            EventType::Sieve(SieveEvent::ActionAcceptReplace) => 397,
            EventType::Sieve(SieveEvent::ActionDiscard) => 398,
            EventType::Sieve(SieveEvent::ActionReject) => 399,
            EventType::Sieve(SieveEvent::ListNotFound) => 400,
            EventType::Sieve(SieveEvent::MessageTooLarge) => 401,
            EventType::Sieve(SieveEvent::NotSupported) => 402,
            EventType::Sieve(SieveEvent::QuotaExceeded) => 403,
            EventType::Sieve(SieveEvent::RuntimeError) => 404,
            EventType::Sieve(SieveEvent::ScriptNotFound) => 405,
            EventType::Sieve(SieveEvent::SendMessage) => 406,
            EventType::Sieve(SieveEvent::UnexpectedError) => 407,
            EventType::Smtp(SmtpEvent::AlreadyAuthenticated) => 408,
            EventType::Smtp(SmtpEvent::ArcFail) => 409,
            EventType::Smtp(SmtpEvent::ArcPass) => 410,
            EventType::Smtp(SmtpEvent::AuthExchangeTooLong) => 411,
            EventType::Smtp(SmtpEvent::AuthMechanismNotSupported) => 412,
            EventType::Smtp(SmtpEvent::AuthNotAllowed) => 413,
            EventType::Smtp(SmtpEvent::CommandNotImplemented) => 414,
            EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded) => 415,
            EventType::Smtp(SmtpEvent::ConnectionEnd) => 416,
            EventType::Smtp(SmtpEvent::ConnectionStart) => 417,
            EventType::Smtp(SmtpEvent::DeliverByDisabled) => 418,
            EventType::Smtp(SmtpEvent::DeliverByInvalid) => 419,
            EventType::Smtp(SmtpEvent::DidNotSayEhlo) => 420,
            EventType::Smtp(SmtpEvent::DkimFail) => 421,
            EventType::Smtp(SmtpEvent::DkimPass) => 422,
            EventType::Smtp(SmtpEvent::DmarcFail) => 423,
            EventType::Smtp(SmtpEvent::DmarcPass) => 424,
            EventType::Smtp(SmtpEvent::DsnDisabled) => 425,
            EventType::Smtp(SmtpEvent::Ehlo) => 426,
            EventType::Smtp(SmtpEvent::EhloExpected) => 427,
            EventType::Smtp(SmtpEvent::Error) => 428,
            EventType::Smtp(SmtpEvent::Expn) => 429,
            EventType::Smtp(SmtpEvent::ExpnDisabled) => 430,
            EventType::Smtp(SmtpEvent::ExpnNotFound) => 431,
            EventType::Smtp(SmtpEvent::FutureReleaseDisabled) => 432,
            EventType::Smtp(SmtpEvent::FutureReleaseInvalid) => 433,
            EventType::Smtp(SmtpEvent::Help) => 434,
            EventType::Smtp(SmtpEvent::InvalidCommand) => 435,
            EventType::Smtp(SmtpEvent::InvalidEhlo) => 436,
            EventType::Smtp(SmtpEvent::InvalidParameter) => 437,
            EventType::Smtp(SmtpEvent::InvalidRecipientAddress) => 438,
            EventType::Smtp(SmtpEvent::InvalidSenderAddress) => 439,
            EventType::Smtp(SmtpEvent::IprevFail) => 440,
            EventType::Smtp(SmtpEvent::IprevPass) => 441,
            EventType::Smtp(SmtpEvent::LhloExpected) => 442,
            EventType::Smtp(SmtpEvent::LoopDetected) => 443,
            EventType::Smtp(SmtpEvent::MailFrom) => 444,
            EventType::Smtp(SmtpEvent::MailFromMissing) => 445,
            EventType::Smtp(SmtpEvent::MailFromRewritten) => 446,
            EventType::Smtp(SmtpEvent::MailFromUnauthenticated) => 447,
            EventType::Smtp(SmtpEvent::MailFromUnauthorized) => 448,
            EventType::Smtp(SmtpEvent::MailboxDoesNotExist) => 449,
            EventType::Smtp(SmtpEvent::MessageParseFailed) => 450,
            EventType::Smtp(SmtpEvent::MessageTooLarge) => 451,
            EventType::Smtp(SmtpEvent::MissingAuthDirectory) => 452,
            EventType::Smtp(SmtpEvent::MissingLocalHostname) => 453,
            EventType::Smtp(SmtpEvent::MtPriorityDisabled) => 454,
            EventType::Smtp(SmtpEvent::MtPriorityInvalid) => 455,
            EventType::Smtp(SmtpEvent::MultipleMailFrom) => 456,
            EventType::Smtp(SmtpEvent::Noop) => 457,
            EventType::Smtp(SmtpEvent::PipeError) => 458,
            EventType::Smtp(SmtpEvent::PipeSuccess) => 459,
            EventType::Smtp(SmtpEvent::Quit) => 460,
            EventType::Smtp(SmtpEvent::RateLimitExceeded) => 461,
            EventType::Smtp(SmtpEvent::RawInput) => 462,
            EventType::Smtp(SmtpEvent::RawOutput) => 463,
            EventType::Smtp(SmtpEvent::RcptTo) => 464,
            EventType::Smtp(SmtpEvent::RcptToDuplicate) => 465,
            EventType::Smtp(SmtpEvent::RcptToMissing) => 466,
            EventType::Smtp(SmtpEvent::RcptToRewritten) => 467,
            EventType::Smtp(SmtpEvent::RelayNotAllowed) => 468,
            EventType::Smtp(SmtpEvent::RemoteIdNotFound) => 469,
            EventType::Smtp(SmtpEvent::RequestTooLarge) => 470,
            EventType::Smtp(SmtpEvent::RequireTlsDisabled) => 471,
            EventType::Smtp(SmtpEvent::Rset) => 472,
            EventType::Smtp(SmtpEvent::SpfEhloFail) => 473,
            EventType::Smtp(SmtpEvent::SpfEhloPass) => 474,
            EventType::Smtp(SmtpEvent::SpfFromFail) => 475,
            EventType::Smtp(SmtpEvent::SpfFromPass) => 476,
            EventType::Smtp(SmtpEvent::StartTls) => 477,
            EventType::Smtp(SmtpEvent::StartTlsAlready) => 478,
            EventType::Smtp(SmtpEvent::StartTlsUnavailable) => 479,
            EventType::Smtp(SmtpEvent::SyntaxError) => 480,
            EventType::Smtp(SmtpEvent::TimeLimitExceeded) => 481,
            EventType::Smtp(SmtpEvent::TooManyInvalidRcpt) => 482,
            EventType::Smtp(SmtpEvent::TooManyMessages) => 483,
            EventType::Smtp(SmtpEvent::TooManyRecipients) => 484,
            EventType::Smtp(SmtpEvent::TransferLimitExceeded) => 485,
            EventType::Smtp(SmtpEvent::UnsupportedParameter) => 486,
            EventType::Smtp(SmtpEvent::Vrfy) => 487,
            EventType::Smtp(SmtpEvent::VrfyDisabled) => 488,
            EventType::Smtp(SmtpEvent::VrfyNotFound) => 489,
            EventType::Spam(SpamEvent::Classify) => 490,
            EventType::Spam(SpamEvent::ClassifyError) => 491,
            EventType::Spam(SpamEvent::ListUpdated) => 492,
            EventType::Spam(SpamEvent::NotEnoughTrainingData) => 493,
            EventType::Spam(SpamEvent::PyzorError) => 494,
            EventType::Spam(SpamEvent::Train) => 495,
            EventType::Spam(SpamEvent::TrainBalance) => 496,
            EventType::Spam(SpamEvent::TrainError) => 497,
            EventType::Spf(SpfEvent::Fail) => 498,
            EventType::Spf(SpfEvent::Neutral) => 499,
            EventType::Spf(SpfEvent::None) => 500,
            EventType::Spf(SpfEvent::Pass) => 501,
            EventType::Spf(SpfEvent::PermError) => 502,
            EventType::Spf(SpfEvent::SoftFail) => 503,
            EventType::Spf(SpfEvent::TempError) => 504,
            EventType::Store(StoreEvent::AssertValueFailed) => 505,
            EventType::Store(StoreEvent::BlobDelete) => 506,
            EventType::Store(StoreEvent::BlobMissingMarker) => 507,
            EventType::Store(StoreEvent::BlobRead) => 508,
            EventType::Store(StoreEvent::BlobWrite) => 509,
            EventType::Store(StoreEvent::CryptoError) => 510,
            EventType::Store(StoreEvent::DataCorruption) => 511,
            EventType::Store(StoreEvent::DataIterate) => 512,
            EventType::Store(StoreEvent::DataWrite) => 513,
            EventType::Store(StoreEvent::DecompressError) => 514,
            EventType::Store(StoreEvent::DeserializeError) => 515,
            EventType::Store(StoreEvent::ElasticsearchError) => 516,
            EventType::Store(StoreEvent::FilesystemError) => 517,
            EventType::Store(StoreEvent::FoundationdbError) => 518,
            EventType::Store(StoreEvent::LdapBind) => 519,
            EventType::Store(StoreEvent::LdapError) => 520,
            EventType::Store(StoreEvent::LdapQuery) => 521,
            EventType::Store(StoreEvent::MysqlError) => 522,
            EventType::Store(StoreEvent::NotConfigured) => 523,
            EventType::Store(StoreEvent::NotFound) => 524,
            EventType::Store(StoreEvent::NotSupported) => 525,
            EventType::Store(StoreEvent::PoolError) => 526,
            EventType::Store(StoreEvent::PostgresqlError) => 527,
            EventType::Store(StoreEvent::RedisError) => 528,
            EventType::Store(StoreEvent::RocksdbError) => 529,
            EventType::Store(StoreEvent::S3Error) => 530,
            EventType::Store(StoreEvent::SqlQuery) => 531,
            EventType::Store(StoreEvent::SqliteError) => 532,
            EventType::Store(StoreEvent::UnexpectedError) => 533,
            EventType::Telemetry(TelemetryEvent::JournalError) => 534,
            EventType::Telemetry(TelemetryEvent::LogError) => 535,
            EventType::Telemetry(TelemetryEvent::OtelExporterError) => 536,
            EventType::Telemetry(TelemetryEvent::OtelMetricsExporterError) => 537,
            EventType::Telemetry(TelemetryEvent::PrometheusExporterError) => 538,
            EventType::Telemetry(TelemetryEvent::WebhookError) => 539,
            EventType::TlsRpt(TlsRptEvent::RecordFetch) => 540,
            EventType::TlsRpt(TlsRptEvent::RecordFetchError) => 541,
            EventType::Tls(TlsEvent::CertificateNotFound) => 542,
            EventType::Tls(TlsEvent::Handshake) => 543,
            EventType::Tls(TlsEvent::HandshakeError) => 544,
            EventType::Tls(TlsEvent::MultipleCertificatesAvailable) => 545,
            EventType::Tls(TlsEvent::NoCertificatesAvailable) => 546,
            EventType::Tls(TlsEvent::NotConfigured) => 547,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(EventType::Acme(AcmeEvent::AuthCompleted)),
            1 => Some(EventType::Acme(AcmeEvent::AuthError)),
            2 => Some(EventType::Acme(AcmeEvent::AuthPending)),
            3 => Some(EventType::Acme(AcmeEvent::AuthStart)),
            4 => Some(EventType::Acme(AcmeEvent::AuthTooManyAttempts)),
            5 => Some(EventType::Acme(AcmeEvent::AuthValid)),
            6 => Some(EventType::Acme(AcmeEvent::ClientMissingSni)),
            7 => Some(EventType::Acme(AcmeEvent::ClientSuppliedSni)),
            8 => Some(EventType::Acme(AcmeEvent::DnsRecordCreated)),
            9 => Some(EventType::Acme(AcmeEvent::DnsRecordCreationFailed)),
            10 => Some(EventType::Acme(AcmeEvent::DnsRecordDeletionFailed)),
            11 => Some(EventType::Acme(AcmeEvent::DnsRecordLookupFailed)),
            12 => Some(EventType::Acme(AcmeEvent::DnsRecordNotPropagated)),
            13 => Some(EventType::Acme(AcmeEvent::DnsRecordPropagated)),
            14 => Some(EventType::Acme(AcmeEvent::DnsRecordPropagationTimeout)),
            15 => Some(EventType::Acme(AcmeEvent::Error)),
            16 => Some(EventType::Acme(AcmeEvent::OrderCompleted)),
            17 => Some(EventType::Acme(AcmeEvent::OrderInvalid)),
            18 => Some(EventType::Acme(AcmeEvent::OrderProcessing)),
            19 => Some(EventType::Acme(AcmeEvent::OrderReady)),
            20 => Some(EventType::Acme(AcmeEvent::OrderStart)),
            21 => Some(EventType::Acme(AcmeEvent::OrderValid)),
            22 => Some(EventType::Acme(AcmeEvent::ProcessCert)),
            23 => Some(EventType::Acme(AcmeEvent::RenewBackoff)),
            24 => Some(EventType::Acme(AcmeEvent::TlsAlpnError)),
            25 => Some(EventType::Acme(AcmeEvent::TlsAlpnReceived)),
            26 => Some(EventType::Acme(AcmeEvent::TokenNotFound)),
            27 => Some(EventType::Arc(ArcEvent::BrokenChain)),
            28 => Some(EventType::Arc(ArcEvent::ChainTooLong)),
            29 => Some(EventType::Arc(ArcEvent::HasHeaderTag)),
            30 => Some(EventType::Arc(ArcEvent::InvalidCv)),
            31 => Some(EventType::Arc(ArcEvent::InvalidInstance)),
            32 => Some(EventType::Arc(ArcEvent::SealerNotFound)),
            33 => Some(EventType::Auth(AuthEvent::Banned)),
            34 => Some(EventType::Auth(AuthEvent::Error)),
            35 => Some(EventType::Auth(AuthEvent::Failed)),
            36 => Some(EventType::Auth(AuthEvent::MissingTotp)),
            37 => Some(EventType::Auth(AuthEvent::Success)),
            38 => Some(EventType::Auth(AuthEvent::TooManyAttempts)),
            39 => Some(EventType::Cluster(ClusterEvent::DecryptionError)),
            40 => Some(EventType::Cluster(ClusterEvent::EmptyPacket)),
            41 => Some(EventType::Cluster(ClusterEvent::Error)),
            42 => Some(EventType::Cluster(ClusterEvent::InvalidPacket)),
            43 => Some(EventType::Cluster(ClusterEvent::OneOrMorePeersOffline)),
            44 => Some(EventType::Cluster(ClusterEvent::PeerAlive)),
            45 => Some(EventType::Cluster(ClusterEvent::PeerBackOnline)),
            46 => Some(EventType::Cluster(ClusterEvent::PeerDiscovered)),
            47 => Some(EventType::Cluster(ClusterEvent::PeerHasConfigChanges)),
            48 => Some(EventType::Cluster(ClusterEvent::PeerHasListChanges)),
            49 => Some(EventType::Cluster(ClusterEvent::PeerLeaving)),
            50 => Some(EventType::Cluster(ClusterEvent::PeerOffline)),
            51 => Some(EventType::Cluster(ClusterEvent::PeerSuspected)),
            52 => Some(EventType::Cluster(ClusterEvent::PeerSuspectedIsAlive)),
            53 => Some(EventType::Config(ConfigEvent::AlreadyUpToDate)),
            54 => Some(EventType::Config(ConfigEvent::BuildError)),
            55 => Some(EventType::Config(ConfigEvent::BuildWarning)),
            56 => Some(EventType::Config(ConfigEvent::DefaultApplied)),
            57 => Some(EventType::Config(ConfigEvent::ExternalKeyIgnored)),
            58 => Some(EventType::Config(ConfigEvent::FetchError)),
            59 => Some(EventType::Config(ConfigEvent::ImportExternal)),
            60 => Some(EventType::Config(ConfigEvent::MacroError)),
            61 => Some(EventType::Config(ConfigEvent::MissingSetting)),
            62 => Some(EventType::Config(ConfigEvent::ParseError)),
            63 => Some(EventType::Config(ConfigEvent::ParseWarning)),
            64 => Some(EventType::Config(ConfigEvent::UnusedSetting)),
            65 => Some(EventType::Config(ConfigEvent::WriteError)),
            66 => Some(EventType::Dane(DaneEvent::AuthenticationFailure)),
            67 => Some(EventType::Dane(DaneEvent::AuthenticationSuccess)),
            68 => Some(EventType::Dane(DaneEvent::CertificateParseError)),
            69 => Some(EventType::Dane(DaneEvent::NoCertificatesFound)),
            70 => Some(EventType::Dane(DaneEvent::TlsaRecordFetch)),
            71 => Some(EventType::Dane(DaneEvent::TlsaRecordFetchError)),
            72 => Some(EventType::Dane(DaneEvent::TlsaRecordInvalid)),
            73 => Some(EventType::Dane(DaneEvent::TlsaRecordMatch)),
            74 => Some(EventType::Dane(DaneEvent::TlsaRecordNotDnssecSigned)),
            75 => Some(EventType::Dane(DaneEvent::TlsaRecordNotFound)),
            76 => Some(EventType::Delivery(DeliveryEvent::AttemptEnd)),
            77 => Some(EventType::Delivery(DeliveryEvent::AttemptStart)),
            78 => Some(EventType::Delivery(DeliveryEvent::Auth)),
            79 => Some(EventType::Delivery(DeliveryEvent::AuthFailed)),
            80 => Some(EventType::Delivery(DeliveryEvent::Completed)),
            81 => Some(EventType::Delivery(DeliveryEvent::ConcurrencyLimitExceeded)),
            82 => Some(EventType::Delivery(DeliveryEvent::Connect)),
            83 => Some(EventType::Delivery(DeliveryEvent::ConnectError)),
            84 => Some(EventType::Delivery(DeliveryEvent::Delivered)),
            85 => Some(EventType::Delivery(DeliveryEvent::DomainDeliveryStart)),
            86 => Some(EventType::Delivery(DeliveryEvent::DoubleBounce)),
            87 => Some(EventType::Delivery(DeliveryEvent::DsnPermFail)),
            88 => Some(EventType::Delivery(DeliveryEvent::DsnSuccess)),
            89 => Some(EventType::Delivery(DeliveryEvent::DsnTempFail)),
            90 => Some(EventType::Delivery(DeliveryEvent::Ehlo)),
            91 => Some(EventType::Delivery(DeliveryEvent::EhloRejected)),
            92 => Some(EventType::Delivery(DeliveryEvent::Failed)),
            93 => Some(EventType::Delivery(DeliveryEvent::GreetingFailed)),
            94 => Some(EventType::Delivery(DeliveryEvent::ImplicitTlsError)),
            95 => Some(EventType::Delivery(DeliveryEvent::IpLookup)),
            96 => Some(EventType::Delivery(DeliveryEvent::IpLookupFailed)),
            97 => Some(EventType::Delivery(DeliveryEvent::MailFrom)),
            98 => Some(EventType::Delivery(DeliveryEvent::MailFromRejected)),
            99 => Some(EventType::Delivery(DeliveryEvent::MessageRejected)),
            100 => Some(EventType::Delivery(DeliveryEvent::MissingOutboundHostname)),
            101 => Some(EventType::Delivery(DeliveryEvent::MxLookup)),
            102 => Some(EventType::Delivery(DeliveryEvent::MxLookupFailed)),
            103 => Some(EventType::Delivery(DeliveryEvent::NullMx)),
            104 => Some(EventType::Delivery(DeliveryEvent::RateLimitExceeded)),
            105 => Some(EventType::Delivery(DeliveryEvent::RawInput)),
            106 => Some(EventType::Delivery(DeliveryEvent::RawOutput)),
            107 => Some(EventType::Delivery(DeliveryEvent::RcptTo)),
            108 => Some(EventType::Delivery(DeliveryEvent::RcptToFailed)),
            109 => Some(EventType::Delivery(DeliveryEvent::RcptToRejected)),
            110 => Some(EventType::Delivery(DeliveryEvent::StartTls)),
            111 => Some(EventType::Delivery(DeliveryEvent::StartTlsDisabled)),
            112 => Some(EventType::Delivery(DeliveryEvent::StartTlsError)),
            113 => Some(EventType::Delivery(DeliveryEvent::StartTlsUnavailable)),
            114 => Some(EventType::Dkim(DkimEvent::Fail)),
            115 => Some(EventType::Dkim(DkimEvent::FailedAuidMatch)),
            116 => Some(EventType::Dkim(DkimEvent::FailedBodyHashMatch)),
            117 => Some(EventType::Dkim(DkimEvent::FailedVerification)),
            118 => Some(EventType::Dkim(DkimEvent::IncompatibleAlgorithms)),
            119 => Some(EventType::Dkim(DkimEvent::Neutral)),
            120 => Some(EventType::Dkim(DkimEvent::None)),
            121 => Some(EventType::Dkim(DkimEvent::Pass)),
            122 => Some(EventType::Dkim(DkimEvent::PermError)),
            123 => Some(EventType::Dkim(DkimEvent::RevokedPublicKey)),
            124 => Some(EventType::Dkim(DkimEvent::SignatureExpired)),
            125 => Some(EventType::Dkim(DkimEvent::SignatureLength)),
            126 => Some(EventType::Dkim(DkimEvent::SignerNotFound)),
            127 => Some(EventType::Dkim(DkimEvent::TempError)),
            128 => Some(EventType::Dkim(DkimEvent::UnsupportedAlgorithm)),
            129 => Some(EventType::Dkim(DkimEvent::UnsupportedCanonicalization)),
            130 => Some(EventType::Dkim(DkimEvent::UnsupportedKeyType)),
            131 => Some(EventType::Dkim(DkimEvent::UnsupportedVersion)),
            132 => Some(EventType::Dmarc(DmarcEvent::Fail)),
            133 => Some(EventType::Dmarc(DmarcEvent::None)),
            134 => Some(EventType::Dmarc(DmarcEvent::Pass)),
            135 => Some(EventType::Dmarc(DmarcEvent::PermError)),
            136 => Some(EventType::Dmarc(DmarcEvent::TempError)),
            137 => Some(EventType::Eval(EvalEvent::DirectoryNotFound)),
            138 => Some(EventType::Eval(EvalEvent::Error)),
            139 => Some(EventType::Eval(EvalEvent::Result)),
            140 => Some(EventType::Eval(EvalEvent::StoreNotFound)),
            141 => Some(EventType::FtsIndex(FtsIndexEvent::BlobNotFound)),
            142 => Some(EventType::FtsIndex(FtsIndexEvent::Index)),
            143 => Some(EventType::FtsIndex(FtsIndexEvent::LockBusy)),
            144 => Some(EventType::FtsIndex(FtsIndexEvent::Locked)),
            145 => Some(EventType::FtsIndex(FtsIndexEvent::MetadataNotFound)),
            146 => Some(EventType::Housekeeper(HousekeeperEvent::PurgeAccounts)),
            147 => Some(EventType::Housekeeper(HousekeeperEvent::PurgeSessions)),
            148 => Some(EventType::Housekeeper(HousekeeperEvent::PurgeStore)),
            149 => Some(EventType::Housekeeper(HousekeeperEvent::Schedule)),
            150 => Some(EventType::Housekeeper(HousekeeperEvent::Start)),
            151 => Some(EventType::Housekeeper(HousekeeperEvent::Stop)),
            152 => Some(EventType::Http(HttpEvent::ConnectionEnd)),
            153 => Some(EventType::Http(HttpEvent::ConnectionStart)),
            154 => Some(EventType::Http(HttpEvent::Error)),
            155 => Some(EventType::Http(HttpEvent::RequestBody)),
            156 => Some(EventType::Http(HttpEvent::RequestUrl)),
            157 => Some(EventType::Http(HttpEvent::ResponseBody)),
            158 => Some(EventType::Http(HttpEvent::XForwardedMissing)),
            159 => Some(EventType::Imap(ImapEvent::Append)),
            160 => Some(EventType::Imap(ImapEvent::Capabilities)),
            161 => Some(EventType::Imap(ImapEvent::Close)),
            162 => Some(EventType::Imap(ImapEvent::ConnectionEnd)),
            163 => Some(EventType::Imap(ImapEvent::ConnectionStart)),
            164 => Some(EventType::Imap(ImapEvent::Copy)),
            165 => Some(EventType::Imap(ImapEvent::CreateMailbox)),
            166 => Some(EventType::Imap(ImapEvent::DeleteMailbox)),
            167 => Some(EventType::Imap(ImapEvent::Enable)),
            168 => Some(EventType::Imap(ImapEvent::Error)),
            169 => Some(EventType::Imap(ImapEvent::Expunge)),
            170 => Some(EventType::Imap(ImapEvent::Fetch)),
            171 => Some(EventType::Imap(ImapEvent::GetAcl)),
            172 => Some(EventType::Imap(ImapEvent::Id)),
            173 => Some(EventType::Imap(ImapEvent::IdleStart)),
            174 => Some(EventType::Imap(ImapEvent::IdleStop)),
            175 => Some(EventType::Imap(ImapEvent::List)),
            176 => Some(EventType::Imap(ImapEvent::ListRights)),
            177 => Some(EventType::Imap(ImapEvent::Logout)),
            178 => Some(EventType::Imap(ImapEvent::Lsub)),
            179 => Some(EventType::Imap(ImapEvent::Move)),
            180 => Some(EventType::Imap(ImapEvent::MyRights)),
            181 => Some(EventType::Imap(ImapEvent::Namespace)),
            182 => Some(EventType::Imap(ImapEvent::Noop)),
            183 => Some(EventType::Imap(ImapEvent::RawInput)),
            184 => Some(EventType::Imap(ImapEvent::RawOutput)),
            185 => Some(EventType::Imap(ImapEvent::RenameMailbox)),
            186 => Some(EventType::Imap(ImapEvent::Search)),
            187 => Some(EventType::Imap(ImapEvent::Select)),
            188 => Some(EventType::Imap(ImapEvent::SetAcl)),
            189 => Some(EventType::Imap(ImapEvent::Sort)),
            190 => Some(EventType::Imap(ImapEvent::Status)),
            191 => Some(EventType::Imap(ImapEvent::Store)),
            192 => Some(EventType::Imap(ImapEvent::Subscribe)),
            193 => Some(EventType::Imap(ImapEvent::Thread)),
            194 => Some(EventType::Imap(ImapEvent::Unsubscribe)),
            195 => Some(EventType::IncomingReport(IncomingReportEvent::AbuseReport)),
            196 => Some(EventType::IncomingReport(
                IncomingReportEvent::ArfParseFailed,
            )),
            197 => Some(EventType::IncomingReport(
                IncomingReportEvent::AuthFailureReport,
            )),
            198 => Some(EventType::IncomingReport(
                IncomingReportEvent::DecompressError,
            )),
            199 => Some(EventType::IncomingReport(
                IncomingReportEvent::DmarcParseFailed,
            )),
            200 => Some(EventType::IncomingReport(IncomingReportEvent::DmarcReport)),
            201 => Some(EventType::IncomingReport(
                IncomingReportEvent::DmarcReportWithWarnings,
            )),
            202 => Some(EventType::IncomingReport(IncomingReportEvent::FraudReport)),
            203 => Some(EventType::IncomingReport(
                IncomingReportEvent::MessageParseFailed,
            )),
            204 => Some(EventType::IncomingReport(
                IncomingReportEvent::NotSpamReport,
            )),
            205 => Some(EventType::IncomingReport(IncomingReportEvent::OtherReport)),
            206 => Some(EventType::IncomingReport(IncomingReportEvent::TlsReport)),
            207 => Some(EventType::IncomingReport(
                IncomingReportEvent::TlsReportWithWarnings,
            )),
            208 => Some(EventType::IncomingReport(
                IncomingReportEvent::TlsRpcParseFailed,
            )),
            209 => Some(EventType::IncomingReport(IncomingReportEvent::VirusReport)),
            210 => Some(EventType::Iprev(IprevEvent::Fail)),
            211 => Some(EventType::Iprev(IprevEvent::None)),
            212 => Some(EventType::Iprev(IprevEvent::Pass)),
            213 => Some(EventType::Iprev(IprevEvent::PermError)),
            214 => Some(EventType::Iprev(IprevEvent::TempError)),
            215 => Some(EventType::Jmap(JmapEvent::AccountNotFound)),
            216 => Some(EventType::Jmap(JmapEvent::AccountNotSupportedByMethod)),
            217 => Some(EventType::Jmap(JmapEvent::AccountReadOnly)),
            218 => Some(EventType::Jmap(JmapEvent::AnchorNotFound)),
            219 => Some(EventType::Jmap(JmapEvent::CannotCalculateChanges)),
            220 => Some(EventType::Jmap(JmapEvent::Forbidden)),
            221 => Some(EventType::Jmap(JmapEvent::InvalidArguments)),
            222 => Some(EventType::Jmap(JmapEvent::InvalidResultReference)),
            223 => Some(EventType::Jmap(JmapEvent::MethodCall)),
            224 => Some(EventType::Jmap(JmapEvent::NotFound)),
            225 => Some(EventType::Jmap(JmapEvent::NotJson)),
            226 => Some(EventType::Jmap(JmapEvent::NotRequest)),
            227 => Some(EventType::Jmap(JmapEvent::RequestTooLarge)),
            228 => Some(EventType::Jmap(JmapEvent::StateMismatch)),
            229 => Some(EventType::Jmap(JmapEvent::UnknownCapability)),
            230 => Some(EventType::Jmap(JmapEvent::UnknownDataType)),
            231 => Some(EventType::Jmap(JmapEvent::UnknownMethod)),
            232 => Some(EventType::Jmap(JmapEvent::UnsupportedFilter)),
            233 => Some(EventType::Jmap(JmapEvent::UnsupportedSort)),
            234 => Some(EventType::Jmap(JmapEvent::WebsocketError)),
            235 => Some(EventType::Jmap(JmapEvent::WebsocketStart)),
            236 => Some(EventType::Jmap(JmapEvent::WebsocketStop)),
            237 => Some(EventType::Limit(LimitEvent::BlobQuota)),
            238 => Some(EventType::Limit(LimitEvent::CallsIn)),
            239 => Some(EventType::Limit(LimitEvent::ConcurrentConnection)),
            240 => Some(EventType::Limit(LimitEvent::ConcurrentRequest)),
            241 => Some(EventType::Limit(LimitEvent::ConcurrentUpload)),
            242 => Some(EventType::Limit(LimitEvent::Quota)),
            243 => Some(EventType::Limit(LimitEvent::SizeRequest)),
            244 => Some(EventType::Limit(LimitEvent::SizeUpload)),
            245 => Some(EventType::Limit(LimitEvent::TooManyRequests)),
            246 => Some(EventType::MailAuth(MailAuthEvent::Base64)),
            247 => Some(EventType::MailAuth(MailAuthEvent::Crypto)),
            248 => Some(EventType::MailAuth(MailAuthEvent::DnsError)),
            249 => Some(EventType::MailAuth(MailAuthEvent::DnsInvalidRecordType)),
            250 => Some(EventType::MailAuth(MailAuthEvent::DnsRecordNotFound)),
            251 => Some(EventType::MailAuth(MailAuthEvent::Io)),
            252 => Some(EventType::MailAuth(MailAuthEvent::MissingParameters)),
            253 => Some(EventType::MailAuth(MailAuthEvent::NoHeadersFound)),
            254 => Some(EventType::MailAuth(MailAuthEvent::ParseError)),
            255 => Some(EventType::MailAuth(MailAuthEvent::PolicyNotAligned)),
            256 => Some(EventType::ManageSieve(ManageSieveEvent::Capabilities)),
            257 => Some(EventType::ManageSieve(ManageSieveEvent::CheckScript)),
            258 => Some(EventType::ManageSieve(ManageSieveEvent::ConnectionEnd)),
            259 => Some(EventType::ManageSieve(ManageSieveEvent::ConnectionStart)),
            260 => Some(EventType::ManageSieve(ManageSieveEvent::CreateScript)),
            261 => Some(EventType::ManageSieve(ManageSieveEvent::DeleteScript)),
            262 => Some(EventType::ManageSieve(ManageSieveEvent::Error)),
            263 => Some(EventType::ManageSieve(ManageSieveEvent::GetScript)),
            264 => Some(EventType::ManageSieve(ManageSieveEvent::HaveSpace)),
            265 => Some(EventType::ManageSieve(ManageSieveEvent::ListScripts)),
            266 => Some(EventType::ManageSieve(ManageSieveEvent::Logout)),
            267 => Some(EventType::ManageSieve(ManageSieveEvent::Noop)),
            268 => Some(EventType::ManageSieve(ManageSieveEvent::RawInput)),
            269 => Some(EventType::ManageSieve(ManageSieveEvent::RawOutput)),
            270 => Some(EventType::ManageSieve(ManageSieveEvent::RenameScript)),
            271 => Some(EventType::ManageSieve(ManageSieveEvent::SetActive)),
            272 => Some(EventType::ManageSieve(ManageSieveEvent::StartTls)),
            273 => Some(EventType::ManageSieve(ManageSieveEvent::Unauthenticate)),
            274 => Some(EventType::ManageSieve(ManageSieveEvent::UpdateScript)),
            275 => Some(EventType::Manage(ManageEvent::AlreadyExists)),
            276 => Some(EventType::Manage(ManageEvent::AssertFailed)),
            277 => Some(EventType::Manage(ManageEvent::Error)),
            278 => Some(EventType::Manage(ManageEvent::MissingParameter)),
            279 => Some(EventType::Manage(ManageEvent::NotFound)),
            280 => Some(EventType::Manage(ManageEvent::NotSupported)),
            281 => Some(EventType::MessageIngest(MessageIngestEvent::Duplicate)),
            282 => Some(EventType::MessageIngest(MessageIngestEvent::Error)),
            283 => Some(EventType::MessageIngest(MessageIngestEvent::Ham)),
            284 => Some(EventType::MessageIngest(MessageIngestEvent::ImapAppend)),
            285 => Some(EventType::MessageIngest(MessageIngestEvent::JmapAppend)),
            286 => Some(EventType::MessageIngest(MessageIngestEvent::Spam)),
            287 => Some(EventType::Milter(MilterEvent::ActionAccept)),
            288 => Some(EventType::Milter(MilterEvent::ActionConnectionFailure)),
            289 => Some(EventType::Milter(MilterEvent::ActionDiscard)),
            290 => Some(EventType::Milter(MilterEvent::ActionReject)),
            291 => Some(EventType::Milter(MilterEvent::ActionReplyCode)),
            292 => Some(EventType::Milter(MilterEvent::ActionShutdown)),
            293 => Some(EventType::Milter(MilterEvent::ActionTempFail)),
            294 => Some(EventType::Milter(MilterEvent::Disconnected)),
            295 => Some(EventType::Milter(MilterEvent::FrameInvalid)),
            296 => Some(EventType::Milter(MilterEvent::FrameTooLarge)),
            297 => Some(EventType::Milter(MilterEvent::IoError)),
            298 => Some(EventType::Milter(MilterEvent::ParseError)),
            299 => Some(EventType::Milter(MilterEvent::Read)),
            300 => Some(EventType::Milter(MilterEvent::Timeout)),
            301 => Some(EventType::Milter(MilterEvent::TlsInvalidName)),
            302 => Some(EventType::Milter(MilterEvent::UnexpectedResponse)),
            303 => Some(EventType::Milter(MilterEvent::Write)),
            304 => Some(EventType::MtaHook(MtaHookEvent::ActionAccept)),
            305 => Some(EventType::MtaHook(MtaHookEvent::ActionDiscard)),
            306 => Some(EventType::MtaHook(MtaHookEvent::ActionQuarantine)),
            307 => Some(EventType::MtaHook(MtaHookEvent::ActionReject)),
            308 => Some(EventType::MtaHook(MtaHookEvent::Error)),
            309 => Some(EventType::MtaSts(MtaStsEvent::Authorized)),
            310 => Some(EventType::MtaSts(MtaStsEvent::InvalidPolicy)),
            311 => Some(EventType::MtaSts(MtaStsEvent::NotAuthorized)),
            312 => Some(EventType::MtaSts(MtaStsEvent::PolicyFetch)),
            313 => Some(EventType::MtaSts(MtaStsEvent::PolicyFetchError)),
            314 => Some(EventType::MtaSts(MtaStsEvent::PolicyNotFound)),
            315 => Some(EventType::Network(NetworkEvent::AcceptError)),
            316 => Some(EventType::Network(NetworkEvent::BindError)),
            317 => Some(EventType::Network(NetworkEvent::Closed)),
            318 => Some(EventType::Network(NetworkEvent::DropBlocked)),
            319 => Some(EventType::Network(NetworkEvent::FlushError)),
            320 => Some(EventType::Network(NetworkEvent::ListenError)),
            321 => Some(EventType::Network(NetworkEvent::ListenStart)),
            322 => Some(EventType::Network(NetworkEvent::ListenStop)),
            323 => Some(EventType::Network(NetworkEvent::ProxyError)),
            324 => Some(EventType::Network(NetworkEvent::ReadError)),
            325 => Some(EventType::Network(NetworkEvent::SetOptError)),
            326 => Some(EventType::Network(NetworkEvent::SplitError)),
            327 => Some(EventType::Network(NetworkEvent::Timeout)),
            328 => Some(EventType::Network(NetworkEvent::WriteError)),
            329 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DkimRateLimited,
            )),
            330 => Some(EventType::OutgoingReport(OutgoingReportEvent::DkimReport)),
            331 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DmarcAggregateReport,
            )),
            332 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::DmarcRateLimited,
            )),
            333 => Some(EventType::OutgoingReport(OutgoingReportEvent::DmarcReport)),
            334 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::HttpSubmission,
            )),
            335 => Some(EventType::OutgoingReport(OutgoingReportEvent::LockBusy)),
            336 => Some(EventType::OutgoingReport(OutgoingReportEvent::LockDeleted)),
            337 => Some(EventType::OutgoingReport(OutgoingReportEvent::Locked)),
            338 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::NoRecipientsFound,
            )),
            339 => Some(EventType::OutgoingReport(OutgoingReportEvent::NotFound)),
            340 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::ReportingAddressValidationError,
            )),
            341 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::SpfRateLimited,
            )),
            342 => Some(EventType::OutgoingReport(OutgoingReportEvent::SpfReport)),
            343 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::SubmissionError,
            )),
            344 => Some(EventType::OutgoingReport(OutgoingReportEvent::TlsAggregate)),
            345 => Some(EventType::OutgoingReport(
                OutgoingReportEvent::UnauthorizedReportingAddress,
            )),
            346 => Some(EventType::Pop3(Pop3Event::Capabilities)),
            347 => Some(EventType::Pop3(Pop3Event::ConnectionEnd)),
            348 => Some(EventType::Pop3(Pop3Event::ConnectionStart)),
            349 => Some(EventType::Pop3(Pop3Event::Delete)),
            350 => Some(EventType::Pop3(Pop3Event::Error)),
            351 => Some(EventType::Pop3(Pop3Event::Fetch)),
            352 => Some(EventType::Pop3(Pop3Event::List)),
            353 => Some(EventType::Pop3(Pop3Event::ListMessage)),
            354 => Some(EventType::Pop3(Pop3Event::Noop)),
            355 => Some(EventType::Pop3(Pop3Event::Quit)),
            356 => Some(EventType::Pop3(Pop3Event::RawInput)),
            357 => Some(EventType::Pop3(Pop3Event::RawOutput)),
            358 => Some(EventType::Pop3(Pop3Event::Reset)),
            359 => Some(EventType::Pop3(Pop3Event::StartTls)),
            360 => Some(EventType::Pop3(Pop3Event::Stat)),
            361 => Some(EventType::Pop3(Pop3Event::Uidl)),
            362 => Some(EventType::Pop3(Pop3Event::UidlMessage)),
            363 => Some(EventType::Pop3(Pop3Event::Utf8)),
            364 => Some(EventType::Purge(PurgeEvent::AutoExpunge)),
            365 => Some(EventType::Purge(PurgeEvent::Error)),
            366 => Some(EventType::Purge(PurgeEvent::Finished)),
            367 => Some(EventType::Purge(PurgeEvent::PurgeActive)),
            368 => Some(EventType::Purge(PurgeEvent::Running)),
            369 => Some(EventType::Purge(PurgeEvent::Started)),
            370 => Some(EventType::Purge(PurgeEvent::TombstoneCleanup)),
            371 => Some(EventType::PushSubscription(PushSubscriptionEvent::Error)),
            372 => Some(EventType::PushSubscription(PushSubscriptionEvent::NotFound)),
            373 => Some(EventType::PushSubscription(PushSubscriptionEvent::Success)),
            374 => Some(EventType::Queue(QueueEvent::BlobNotFound)),
            375 => Some(EventType::Queue(QueueEvent::ConcurrencyLimitExceeded)),
            376 => Some(EventType::Queue(QueueEvent::LockBusy)),
            377 => Some(EventType::Queue(QueueEvent::Locked)),
            378 => Some(EventType::Queue(QueueEvent::QueueAutogenerated)),
            379 => Some(EventType::Queue(QueueEvent::QueueDsn)),
            380 => Some(EventType::Queue(QueueEvent::QueueMessage)),
            381 => Some(EventType::Queue(QueueEvent::QueueMessageAuthenticated)),
            382 => Some(EventType::Queue(QueueEvent::QueueReport)),
            383 => Some(EventType::Queue(QueueEvent::QuotaExceeded)),
            384 => Some(EventType::Queue(QueueEvent::RateLimitExceeded)),
            385 => Some(EventType::Queue(QueueEvent::Rescheduled)),
            386 => Some(EventType::Resource(ResourceEvent::BadParameters)),
            387 => Some(EventType::Resource(ResourceEvent::DownloadExternal)),
            388 => Some(EventType::Resource(ResourceEvent::Error)),
            389 => Some(EventType::Resource(ResourceEvent::NotFound)),
            390 => Some(EventType::Resource(ResourceEvent::WebadminUnpacked)),
            391 => Some(EventType::Server(ServerEvent::Licensing)),
            392 => Some(EventType::Server(ServerEvent::Shutdown)),
            393 => Some(EventType::Server(ServerEvent::Startup)),
            394 => Some(EventType::Server(ServerEvent::StartupError)),
            395 => Some(EventType::Server(ServerEvent::ThreadError)),
            396 => Some(EventType::Sieve(SieveEvent::ActionAccept)),
            397 => Some(EventType::Sieve(SieveEvent::ActionAcceptReplace)),
            398 => Some(EventType::Sieve(SieveEvent::ActionDiscard)),
            399 => Some(EventType::Sieve(SieveEvent::ActionReject)),
            400 => Some(EventType::Sieve(SieveEvent::ListNotFound)),
            401 => Some(EventType::Sieve(SieveEvent::MessageTooLarge)),
            402 => Some(EventType::Sieve(SieveEvent::NotSupported)),
            403 => Some(EventType::Sieve(SieveEvent::QuotaExceeded)),
            404 => Some(EventType::Sieve(SieveEvent::RuntimeError)),
            405 => Some(EventType::Sieve(SieveEvent::ScriptNotFound)),
            406 => Some(EventType::Sieve(SieveEvent::SendMessage)),
            407 => Some(EventType::Sieve(SieveEvent::UnexpectedError)),
            408 => Some(EventType::Smtp(SmtpEvent::AlreadyAuthenticated)),
            409 => Some(EventType::Smtp(SmtpEvent::ArcFail)),
            410 => Some(EventType::Smtp(SmtpEvent::ArcPass)),
            411 => Some(EventType::Smtp(SmtpEvent::AuthExchangeTooLong)),
            412 => Some(EventType::Smtp(SmtpEvent::AuthMechanismNotSupported)),
            413 => Some(EventType::Smtp(SmtpEvent::AuthNotAllowed)),
            414 => Some(EventType::Smtp(SmtpEvent::CommandNotImplemented)),
            415 => Some(EventType::Smtp(SmtpEvent::ConcurrencyLimitExceeded)),
            416 => Some(EventType::Smtp(SmtpEvent::ConnectionEnd)),
            417 => Some(EventType::Smtp(SmtpEvent::ConnectionStart)),
            418 => Some(EventType::Smtp(SmtpEvent::DeliverByDisabled)),
            419 => Some(EventType::Smtp(SmtpEvent::DeliverByInvalid)),
            420 => Some(EventType::Smtp(SmtpEvent::DidNotSayEhlo)),
            421 => Some(EventType::Smtp(SmtpEvent::DkimFail)),
            422 => Some(EventType::Smtp(SmtpEvent::DkimPass)),
            423 => Some(EventType::Smtp(SmtpEvent::DmarcFail)),
            424 => Some(EventType::Smtp(SmtpEvent::DmarcPass)),
            425 => Some(EventType::Smtp(SmtpEvent::DsnDisabled)),
            426 => Some(EventType::Smtp(SmtpEvent::Ehlo)),
            427 => Some(EventType::Smtp(SmtpEvent::EhloExpected)),
            428 => Some(EventType::Smtp(SmtpEvent::Error)),
            429 => Some(EventType::Smtp(SmtpEvent::Expn)),
            430 => Some(EventType::Smtp(SmtpEvent::ExpnDisabled)),
            431 => Some(EventType::Smtp(SmtpEvent::ExpnNotFound)),
            432 => Some(EventType::Smtp(SmtpEvent::FutureReleaseDisabled)),
            433 => Some(EventType::Smtp(SmtpEvent::FutureReleaseInvalid)),
            434 => Some(EventType::Smtp(SmtpEvent::Help)),
            435 => Some(EventType::Smtp(SmtpEvent::InvalidCommand)),
            436 => Some(EventType::Smtp(SmtpEvent::InvalidEhlo)),
            437 => Some(EventType::Smtp(SmtpEvent::InvalidParameter)),
            438 => Some(EventType::Smtp(SmtpEvent::InvalidRecipientAddress)),
            439 => Some(EventType::Smtp(SmtpEvent::InvalidSenderAddress)),
            440 => Some(EventType::Smtp(SmtpEvent::IprevFail)),
            441 => Some(EventType::Smtp(SmtpEvent::IprevPass)),
            442 => Some(EventType::Smtp(SmtpEvent::LhloExpected)),
            443 => Some(EventType::Smtp(SmtpEvent::LoopDetected)),
            444 => Some(EventType::Smtp(SmtpEvent::MailFrom)),
            445 => Some(EventType::Smtp(SmtpEvent::MailFromMissing)),
            446 => Some(EventType::Smtp(SmtpEvent::MailFromRewritten)),
            447 => Some(EventType::Smtp(SmtpEvent::MailFromUnauthenticated)),
            448 => Some(EventType::Smtp(SmtpEvent::MailFromUnauthorized)),
            449 => Some(EventType::Smtp(SmtpEvent::MailboxDoesNotExist)),
            450 => Some(EventType::Smtp(SmtpEvent::MessageParseFailed)),
            451 => Some(EventType::Smtp(SmtpEvent::MessageTooLarge)),
            452 => Some(EventType::Smtp(SmtpEvent::MissingAuthDirectory)),
            453 => Some(EventType::Smtp(SmtpEvent::MissingLocalHostname)),
            454 => Some(EventType::Smtp(SmtpEvent::MtPriorityDisabled)),
            455 => Some(EventType::Smtp(SmtpEvent::MtPriorityInvalid)),
            456 => Some(EventType::Smtp(SmtpEvent::MultipleMailFrom)),
            457 => Some(EventType::Smtp(SmtpEvent::Noop)),
            458 => Some(EventType::Smtp(SmtpEvent::PipeError)),
            459 => Some(EventType::Smtp(SmtpEvent::PipeSuccess)),
            460 => Some(EventType::Smtp(SmtpEvent::Quit)),
            461 => Some(EventType::Smtp(SmtpEvent::RateLimitExceeded)),
            462 => Some(EventType::Smtp(SmtpEvent::RawInput)),
            463 => Some(EventType::Smtp(SmtpEvent::RawOutput)),
            464 => Some(EventType::Smtp(SmtpEvent::RcptTo)),
            465 => Some(EventType::Smtp(SmtpEvent::RcptToDuplicate)),
            466 => Some(EventType::Smtp(SmtpEvent::RcptToMissing)),
            467 => Some(EventType::Smtp(SmtpEvent::RcptToRewritten)),
            468 => Some(EventType::Smtp(SmtpEvent::RelayNotAllowed)),
            469 => Some(EventType::Smtp(SmtpEvent::RemoteIdNotFound)),
            470 => Some(EventType::Smtp(SmtpEvent::RequestTooLarge)),
            471 => Some(EventType::Smtp(SmtpEvent::RequireTlsDisabled)),
            472 => Some(EventType::Smtp(SmtpEvent::Rset)),
            473 => Some(EventType::Smtp(SmtpEvent::SpfEhloFail)),
            474 => Some(EventType::Smtp(SmtpEvent::SpfEhloPass)),
            475 => Some(EventType::Smtp(SmtpEvent::SpfFromFail)),
            476 => Some(EventType::Smtp(SmtpEvent::SpfFromPass)),
            477 => Some(EventType::Smtp(SmtpEvent::StartTls)),
            478 => Some(EventType::Smtp(SmtpEvent::StartTlsAlready)),
            479 => Some(EventType::Smtp(SmtpEvent::StartTlsUnavailable)),
            480 => Some(EventType::Smtp(SmtpEvent::SyntaxError)),
            481 => Some(EventType::Smtp(SmtpEvent::TimeLimitExceeded)),
            482 => Some(EventType::Smtp(SmtpEvent::TooManyInvalidRcpt)),
            483 => Some(EventType::Smtp(SmtpEvent::TooManyMessages)),
            484 => Some(EventType::Smtp(SmtpEvent::TooManyRecipients)),
            485 => Some(EventType::Smtp(SmtpEvent::TransferLimitExceeded)),
            486 => Some(EventType::Smtp(SmtpEvent::UnsupportedParameter)),
            487 => Some(EventType::Smtp(SmtpEvent::Vrfy)),
            488 => Some(EventType::Smtp(SmtpEvent::VrfyDisabled)),
            489 => Some(EventType::Smtp(SmtpEvent::VrfyNotFound)),
            490 => Some(EventType::Spam(SpamEvent::Classify)),
            491 => Some(EventType::Spam(SpamEvent::ClassifyError)),
            492 => Some(EventType::Spam(SpamEvent::ListUpdated)),
            493 => Some(EventType::Spam(SpamEvent::NotEnoughTrainingData)),
            494 => Some(EventType::Spam(SpamEvent::PyzorError)),
            495 => Some(EventType::Spam(SpamEvent::Train)),
            496 => Some(EventType::Spam(SpamEvent::TrainBalance)),
            497 => Some(EventType::Spam(SpamEvent::TrainError)),
            498 => Some(EventType::Spf(SpfEvent::Fail)),
            499 => Some(EventType::Spf(SpfEvent::Neutral)),
            500 => Some(EventType::Spf(SpfEvent::None)),
            501 => Some(EventType::Spf(SpfEvent::Pass)),
            502 => Some(EventType::Spf(SpfEvent::PermError)),
            503 => Some(EventType::Spf(SpfEvent::SoftFail)),
            504 => Some(EventType::Spf(SpfEvent::TempError)),
            505 => Some(EventType::Store(StoreEvent::AssertValueFailed)),
            506 => Some(EventType::Store(StoreEvent::BlobDelete)),
            507 => Some(EventType::Store(StoreEvent::BlobMissingMarker)),
            508 => Some(EventType::Store(StoreEvent::BlobRead)),
            509 => Some(EventType::Store(StoreEvent::BlobWrite)),
            510 => Some(EventType::Store(StoreEvent::CryptoError)),
            511 => Some(EventType::Store(StoreEvent::DataCorruption)),
            512 => Some(EventType::Store(StoreEvent::DataIterate)),
            513 => Some(EventType::Store(StoreEvent::DataWrite)),
            514 => Some(EventType::Store(StoreEvent::DecompressError)),
            515 => Some(EventType::Store(StoreEvent::DeserializeError)),
            516 => Some(EventType::Store(StoreEvent::ElasticsearchError)),
            517 => Some(EventType::Store(StoreEvent::FilesystemError)),
            518 => Some(EventType::Store(StoreEvent::FoundationdbError)),
            519 => Some(EventType::Store(StoreEvent::LdapBind)),
            520 => Some(EventType::Store(StoreEvent::LdapError)),
            521 => Some(EventType::Store(StoreEvent::LdapQuery)),
            522 => Some(EventType::Store(StoreEvent::MysqlError)),
            523 => Some(EventType::Store(StoreEvent::NotConfigured)),
            524 => Some(EventType::Store(StoreEvent::NotFound)),
            525 => Some(EventType::Store(StoreEvent::NotSupported)),
            526 => Some(EventType::Store(StoreEvent::PoolError)),
            527 => Some(EventType::Store(StoreEvent::PostgresqlError)),
            528 => Some(EventType::Store(StoreEvent::RedisError)),
            529 => Some(EventType::Store(StoreEvent::RocksdbError)),
            530 => Some(EventType::Store(StoreEvent::S3Error)),
            531 => Some(EventType::Store(StoreEvent::SqlQuery)),
            532 => Some(EventType::Store(StoreEvent::SqliteError)),
            533 => Some(EventType::Store(StoreEvent::UnexpectedError)),
            534 => Some(EventType::Telemetry(TelemetryEvent::JournalError)),
            535 => Some(EventType::Telemetry(TelemetryEvent::LogError)),
            536 => Some(EventType::Telemetry(TelemetryEvent::OtelExporterError)),
            537 => Some(EventType::Telemetry(
                TelemetryEvent::OtelMetricsExporterError,
            )),
            538 => Some(EventType::Telemetry(
                TelemetryEvent::PrometheusExporterError,
            )),
            539 => Some(EventType::Telemetry(TelemetryEvent::WebhookError)),
            540 => Some(EventType::TlsRpt(TlsRptEvent::RecordFetch)),
            541 => Some(EventType::TlsRpt(TlsRptEvent::RecordFetchError)),
            542 => Some(EventType::Tls(TlsEvent::CertificateNotFound)),
            543 => Some(EventType::Tls(TlsEvent::Handshake)),
            544 => Some(EventType::Tls(TlsEvent::HandshakeError)),
            545 => Some(EventType::Tls(TlsEvent::MultipleCertificatesAvailable)),
            546 => Some(EventType::Tls(TlsEvent::NoCertificatesAvailable)),
            547 => Some(EventType::Tls(TlsEvent::NotConfigured)),
            _ => None,
        }
    }
}

impl Key {
    fn code(&self) -> u64 {
        match self {
            Key::AccountName => 0,
            Key::AccountId => 1,
            Key::BlobId => 2,
            Key::CausedBy => 3,
            Key::ChangeId => 4,
            Key::Code => 5,
            Key::Collection => 6,
            Key::Contents => 7,
            Key::Details => 8,
            Key::DkimFail => 9,
            Key::DkimNone => 10,
            Key::DkimPass => 11,
            Key::DmarcNone => 12,
            Key::DmarcPass => 13,
            Key::DmarcQuarantine => 14,
            Key::DmarcReject => 15,
            Key::DocumentId => 16,
            Key::Domain => 17,
            Key::Due => 18,
            Key::Elapsed => 19,
            Key::Expires => 20,
            Key::From => 21,
            Key::Hostname => 22,
            Key::Id => 23,
            Key::Key => 24,
            Key::Limit => 25,
            Key::ListenerId => 26,
            Key::LocalIp => 27,
            Key::LocalPort => 28,
            Key::MailboxName => 29,
            Key::MailboxId => 30,
            Key::MessageId => 31,
            Key::NextDsn => 32,
            Key::NextRetry => 33,
            Key::Path => 34,
            Key::Policy => 35,
            Key::QueueId => 36,
            Key::RangeFrom => 37,
            Key::RangeTo => 38,
            Key::Reason => 39,
            Key::RemoteIp => 40,
            Key::RemotePort => 41,
            Key::ReportId => 42,
            Key::Result => 43,
            Key::Size => 44,
            Key::Source => 45,
            Key::SpanId => 46,
            Key::SpfFail => 47,
            Key::SpfNone => 48,
            Key::SpfPass => 49,
            Key::Strict => 50,
            Key::Tls => 51,
            Key::To => 52,
            Key::Total => 53,
            Key::TotalFailures => 54,
            Key::TotalSuccesses => 55,
            Key::Type => 56,
            Key::Uid => 57,
            Key::UidNext => 58,
            Key::UidValidity => 59,
            Key::Url => 60,
            Key::ValidFrom => 61,
            Key::ValidTo => 62,
            Key::Value => 63,
            Key::Version => 64,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Key::AccountName),
            1 => Some(Key::AccountId),
            2 => Some(Key::BlobId),
            3 => Some(Key::CausedBy),
            4 => Some(Key::ChangeId),
            5 => Some(Key::Code),
            6 => Some(Key::Collection),
            7 => Some(Key::Contents),
            8 => Some(Key::Details),
            9 => Some(Key::DkimFail),
            10 => Some(Key::DkimNone),
            11 => Some(Key::DkimPass),
            12 => Some(Key::DmarcNone),
            13 => Some(Key::DmarcPass),
            14 => Some(Key::DmarcQuarantine),
            15 => Some(Key::DmarcReject),
            16 => Some(Key::DocumentId),
            17 => Some(Key::Domain),
            18 => Some(Key::Due),
            19 => Some(Key::Elapsed),
            20 => Some(Key::Expires),
            21 => Some(Key::From),
            22 => Some(Key::Hostname),
            23 => Some(Key::Id),
            24 => Some(Key::Key),
            25 => Some(Key::Limit),
            26 => Some(Key::ListenerId),
            27 => Some(Key::LocalIp),
            28 => Some(Key::LocalPort),
            29 => Some(Key::MailboxName),
            30 => Some(Key::MailboxId),
            31 => Some(Key::MessageId),
            32 => Some(Key::NextDsn),
            33 => Some(Key::NextRetry),
            34 => Some(Key::Path),
            35 => Some(Key::Policy),
            36 => Some(Key::QueueId),
            37 => Some(Key::RangeFrom),
            38 => Some(Key::RangeTo),
            39 => Some(Key::Reason),
            40 => Some(Key::RemoteIp),
            41 => Some(Key::RemotePort),
            42 => Some(Key::ReportId),
            43 => Some(Key::Result),
            44 => Some(Key::Size),
            45 => Some(Key::Source),
            46 => Some(Key::SpanId),
            47 => Some(Key::SpfFail),
            48 => Some(Key::SpfNone),
            49 => Some(Key::SpfPass),
            50 => Some(Key::Strict),
            51 => Some(Key::Tls),
            52 => Some(Key::To),
            53 => Some(Key::Total),
            54 => Some(Key::TotalFailures),
            55 => Some(Key::TotalSuccesses),
            56 => Some(Key::Type),
            57 => Some(Key::Uid),
            58 => Some(Key::UidNext),
            59 => Some(Key::UidValidity),
            60 => Some(Key::Url),
            61 => Some(Key::ValidFrom),
            62 => Some(Key::ValidTo),
            63 => Some(Key::Value),
            64 => Some(Key::Version),
            _ => None,
        }
    }
}
