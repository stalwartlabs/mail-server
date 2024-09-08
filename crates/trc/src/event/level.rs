/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, fmt::Display, str::FromStr};

use super::*;

impl EventType {
    pub fn level(&self) -> Level {
        match self {
            EventType::Store(event) => match event {
                StoreEvent::DataWrite
                | StoreEvent::DataIterate
                | StoreEvent::BlobRead
                | StoreEvent::BlobWrite
                | StoreEvent::BlobDelete
                | StoreEvent::SqlQuery
                | StoreEvent::LdapQuery
                | StoreEvent::LdapBind => Level::Trace,
                StoreEvent::NotFound => Level::Debug,
                StoreEvent::AssertValueFailed
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
                ImapEvent::ConnectionStart | ImapEvent::ConnectionEnd => Level::Info,
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
                ManageSieveEvent::ConnectionStart | ManageSieveEvent::ConnectionEnd => Level::Info,
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
                Pop3Event::ConnectionStart | Pop3Event::ConnectionEnd => Level::Info,
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
                SmtpEvent::ConnectionStart | SmtpEvent::ConnectionEnd => Level::Info,
                SmtpEvent::DidNotSayEhlo
                | SmtpEvent::EhloExpected
                | SmtpEvent::LhloExpected
                | SmtpEvent::MailFromUnauthenticated
                | SmtpEvent::MailFromUnauthorized
                | SmtpEvent::MailFromRewritten
                | SmtpEvent::MailFromMissing
                | SmtpEvent::MultipleMailFrom
                | SmtpEvent::MailFromNotAllowed
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
                NetworkEvent::ListenStart | NetworkEvent::ListenStop => Level::Info,
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
                | ConfigEvent::AlreadyUpToDate
                | ConfigEvent::ExternalKeyIgnored => Level::Debug,
                ConfigEvent::ParseWarning | ConfigEvent::BuildWarning => Level::Warn,
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
                EvalEvent::Error | EvalEvent::StoreNotFound => Level::Debug,
                EvalEvent::Result => Level::Trace,
                EvalEvent::DirectoryNotFound => Level::Warn,
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
                | SieveEvent::MessageTooLarge => Level::Warn,
                SieveEvent::SendMessage => Level::Info,
                SieveEvent::UnexpectedError => Level::Error,
                SieveEvent::ActionAccept
                | SieveEvent::RuntimeError
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
                HttpEvent::ConnectionStart | HttpEvent::ConnectionEnd => Level::Info,
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
                | HousekeeperEvent::Stop => Level::Info,
                HousekeeperEvent::Schedule => Level::Debug,
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
                QueueEvent::QueueMessage
                | QueueEvent::QueueMessageAuthenticated
                | QueueEvent::QueueReport
                | QueueEvent::QueueDsn
                | QueueEvent::QueueAutogenerated
                | QueueEvent::RateLimitExceeded
                | QueueEvent::ConcurrencyLimitExceeded
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
            EventType::Telemetry(_) => Level::Warn,
            EventType::MessageIngest(event) => match event {
                MessageIngestEvent::Ham
                | MessageIngestEvent::Spam
                | MessageIngestEvent::ImapAppend
                | MessageIngestEvent::JmapAppend
                | MessageIngestEvent::Duplicate => Level::Info,
                MessageIngestEvent::Error => Level::Error,
            },
            EventType::Security(_) => Level::Info,
        }
    }
}

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
