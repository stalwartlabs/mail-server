/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;

impl EventType {
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
            EventType::Telemetry(event) => event.description(),
            EventType::MessageIngest(event) => event.description(),
        }
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
            HttpEvent::ConnectionStart => "HTTP connection started",
            HttpEvent::ConnectionEnd => "HTTP connection ended",
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
            ImapEvent::ConnectionStart => "IMAP connection started",
            ImapEvent::ConnectionEnd => "IMAP connection ended",
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
            Pop3Event::ConnectionStart => "POP3 connection started",
            Pop3Event::ConnectionEnd => "POP3 connection ended",
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
            ManageSieveEvent::ConnectionStart => "ManageSieve connection started",
            ManageSieveEvent::ConnectionEnd => "ManageSieve connection ended",
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
            SmtpEvent::ConnectionStart => "SMTP connection started",
            SmtpEvent::ConnectionEnd => "SMTP connection ended",
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
            QueueEvent::Rescheduled => "Message rescheduled for delivery",
            QueueEvent::LockBusy => "Queue lock is busy",
            QueueEvent::Locked => "Queue is locked",
            QueueEvent::BlobNotFound => "Message blob not found",
            QueueEvent::RateLimitExceeded => "Rate limit exceeded",
            QueueEvent::ConcurrencyLimitExceeded => "Concurrency limit exceeded",
            QueueEvent::QuotaExceeded => "Quota exceeded",
            QueueEvent::QueueMessage => "Queued message for delivery",
            QueueEvent::QueueMessageSubmission => "Queued message submissions for delivery",
            QueueEvent::QueueReport => "Queued report for delivery",
            QueueEvent::QueueDsn => "Queued DSN for delivery",
            QueueEvent::QueueAutogenerated => "Queued autogenerated message for delivery",
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

impl TelemetryEvent {
    pub fn description(&self) -> &'static str {
        match self {
            TelemetryEvent::LogError => "Log collector error",
            TelemetryEvent::WebhookError => "Webhook collector error",
            TelemetryEvent::JournalError => "Journal collector error",
            TelemetryEvent::OtelExporterError => "OpenTelemetry exporter error",
            TelemetryEvent::OtelMetricsExporterError => "OpenTelemetry metrics exporter error",
            TelemetryEvent::PrometheusExporterError => "Prometheus exporter error",
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
            StoreEvent::SqlQuery => "SQL query executed",
            StoreEvent::LdapQuery => "LDAP query executed",
            StoreEvent::LdapBind => "LDAP bind operation",
            StoreEvent::DataWrite => "Write batch operation",
            StoreEvent::BlobRead => "Blob read operation",
            StoreEvent::BlobWrite => "Blob write operation",
            StoreEvent::BlobDelete => "Blob delete operation",
            StoreEvent::DataIterate => "Data store iteration operation",
        }
    }
}

impl MessageIngestEvent {
    pub fn description(&self) -> &'static str {
        match self {
            MessageIngestEvent::Ham => "Message ingested",
            MessageIngestEvent::Spam => "Possible spam message ingested",
            MessageIngestEvent::ImapAppend => "Message appended via IMAP",
            MessageIngestEvent::JmapAppend => "Message appended via JMAP",
            MessageIngestEvent::Duplicate => "Skipping duplicate message",
            MessageIngestEvent::Error => "Message ingestion error",
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
