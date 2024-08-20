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

    pub fn explain(&self) -> &'static str {
        match self {
            EventType::Store(event) => event.explain(),
            EventType::Jmap(event) => event.explain(),
            EventType::Imap(event) => event.explain(),
            EventType::ManageSieve(event) => event.explain(),
            EventType::Pop3(event) => event.explain(),
            EventType::Smtp(event) => event.explain(),
            EventType::Network(event) => event.explain(),
            EventType::Limit(event) => event.explain(),
            EventType::Manage(event) => event.explain(),
            EventType::Auth(event) => event.explain(),
            EventType::Config(event) => event.explain(),
            EventType::Resource(event) => event.explain(),
            EventType::Sieve(event) => event.explain(),
            EventType::Spam(event) => event.explain(),
            EventType::Server(event) => event.explain(),
            EventType::Purge(event) => event.explain(),
            EventType::Eval(event) => event.explain(),
            EventType::Acme(event) => event.explain(),
            EventType::Http(event) => event.explain(),
            EventType::Arc(event) => event.explain(),
            EventType::Dkim(event) => event.explain(),
            EventType::Dmarc(event) => event.explain(),
            EventType::Iprev(event) => event.explain(),
            EventType::Dane(event) => event.explain(),
            EventType::Spf(event) => event.explain(),
            EventType::MailAuth(event) => event.explain(),
            EventType::Tls(event) => event.explain(),
            EventType::PushSubscription(event) => event.explain(),
            EventType::Cluster(event) => event.explain(),
            EventType::Housekeeper(event) => event.explain(),
            EventType::FtsIndex(event) => event.explain(),
            EventType::Milter(event) => event.explain(),
            EventType::MtaHook(event) => event.explain(),
            EventType::Delivery(event) => event.explain(),
            EventType::Queue(event) => event.explain(),
            EventType::TlsRpt(event) => event.explain(),
            EventType::MtaSts(event) => event.explain(),
            EventType::IncomingReport(event) => event.explain(),
            EventType::OutgoingReport(event) => event.explain(),
            EventType::Telemetry(event) => event.explain(),
            EventType::MessageIngest(event) => event.explain(),
        }
    }
}

impl HttpEvent {
    pub fn description(&self) -> &'static str {
        match self {
            HttpEvent::Error => "HTTP error occurred",
            HttpEvent::RequestUrl => "HTTP request URL",
            HttpEvent::RequestBody => "HTTP request body",
            HttpEvent::ResponseBody => "HTTP response body",
            HttpEvent::XForwardedMissing => "X-Forwarded-For header is missing",
            HttpEvent::ConnectionStart => "HTTP connection started",
            HttpEvent::ConnectionEnd => "HTTP connection ended",
        }
    }

    pub fn explain(&self) -> &'static str {
        match self {
            HttpEvent::Error => "An error occurred during an HTTP request",
            HttpEvent::RequestUrl => "The URL of an HTTP request",
            HttpEvent::RequestBody => "The body of an HTTP request",
            HttpEvent::ResponseBody => "The body of an HTTP response",
            HttpEvent::XForwardedMissing => "The X-Forwarded-For header is missing",
            HttpEvent::ConnectionStart => "An HTTP connection was started",
            HttpEvent::ConnectionEnd => "An HTTP connection was ended",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ClusterEvent::PeerAlive => "A peer is alive and reachable",
            ClusterEvent::PeerDiscovered => "A new peer was discovered",
            ClusterEvent::PeerOffline => "A peer is offline",
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
            ClusterEvent::Error => "An error occurred in the cluster",
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

    pub fn explain(&self) -> &'static str {
        match self {
            HousekeeperEvent::Start => "The housekeeper process has started",
            HousekeeperEvent::Stop => "The housekeeper process has stopped",
            HousekeeperEvent::Schedule => "A housekeeper task has been scheduled",
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

    pub fn explain(&self) -> &'static str {
        match self {
            FtsIndexEvent::Index => "The full-text search index has been updated",
            FtsIndexEvent::Locked => "The full-text search index is locked",
            FtsIndexEvent::LockBusy => "The full-text search index lock is busy",
            FtsIndexEvent::BlobNotFound => "The blob was not found for full-text indexing",
            FtsIndexEvent::MetadataNotFound => "The metadata was not found for full-text indexing",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ImapEvent::GetAcl => "Client requested mailbox ACL",
            ImapEvent::SetAcl => "Client set mailbox ACL",
            ImapEvent::MyRights => "Client requested mailbox rights",
            ImapEvent::ListRights => "Client requested mailbox rights list",
            ImapEvent::Append => "Client appended a message to a mailbox",
            ImapEvent::Capabilities => "Client requested server capabilities",
            ImapEvent::Id => "Client sent an ID command",
            ImapEvent::Close => "Client closed a mailbox",
            ImapEvent::Copy => "Client copied messages between mailboxes",
            ImapEvent::Move => "Client moved messages between mailboxes",
            ImapEvent::CreateMailbox => "Client created a mailbox",
            ImapEvent::DeleteMailbox => "Client deleted a mailbox",
            ImapEvent::RenameMailbox => "Client renamed a mailbox",
            ImapEvent::Enable => "Client enabled an extension",
            ImapEvent::Expunge => "Client expunged messages",
            ImapEvent::Fetch => "Client fetched messages",
            ImapEvent::IdleStart => "Client started IDLE",
            ImapEvent::IdleStop => "Client stopped IDLE",
            ImapEvent::List => "Client listed mailboxes",
            ImapEvent::Lsub => "Client listed subscribed mailboxes",
            ImapEvent::Logout => "Client logged out",
            ImapEvent::Namespace => "Client requested namespace",
            ImapEvent::Noop => "Client sent a NOOP command",
            ImapEvent::Search => "Client searched for messages",
            ImapEvent::Sort => "Client sorted messages",
            ImapEvent::Select => "Client selected a mailbox",
            ImapEvent::Status => "Client requested mailbox status",
            ImapEvent::Store => "Client stored flags",
            ImapEvent::Subscribe => "Client subscribed to a mailbox",
            ImapEvent::Unsubscribe => "Client unsubscribed from a mailbox",
            ImapEvent::Thread => "Client requested message threads",
            ImapEvent::Error => "An error occurred during an IMAP command",
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

    pub fn explain(&self) -> &'static str {
        match self {
            Pop3Event::Delete => "Client deleted a message",
            Pop3Event::Reset => "Client reset the session",
            Pop3Event::Quit => "Client quit the session",
            Pop3Event::Fetch => "Client fetched a message",
            Pop3Event::List => "Client listed messages",
            Pop3Event::ListMessage => "Client listed a specific message",
            Pop3Event::Uidl => "Client requested unique identifiers",
            Pop3Event::UidlMessage => "Client requested a specific unique identifier",
            Pop3Event::Stat => "Client requested mailbox status",
            Pop3Event::Noop => "Client sent a NOOP command",
            Pop3Event::Capabilities => "Client requested server capabilities",
            Pop3Event::StartTls => "Client requested TLS",
            Pop3Event::Utf8 => "Client requested UTF-8 support",
            Pop3Event::Error => "An error occurred during a POP3 command",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ManageSieveEvent::CreateScript => "Client created a script",
            ManageSieveEvent::UpdateScript => "Client updated a script",
            ManageSieveEvent::GetScript => "Client fetched a script",
            ManageSieveEvent::DeleteScript => "Client deleted a script",
            ManageSieveEvent::RenameScript => "Client renamed a script",
            ManageSieveEvent::CheckScript => "Client checked a script",
            ManageSieveEvent::HaveSpace => "Client checked for space",
            ManageSieveEvent::ListScripts => "Client listed scripts",
            ManageSieveEvent::SetActive => "Client set an active script",
            ManageSieveEvent::Capabilities => "Client requested server capabilities",
            ManageSieveEvent::StartTls => "Client requested TLS",
            ManageSieveEvent::Unauthenticate => "Client unauthenticated",
            ManageSieveEvent::Logout => "Client logged out",
            ManageSieveEvent::Noop => "Client sent a NOOP command",
            ManageSieveEvent::Error => "An error occurred during a ManageSieve command",
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
            SmtpEvent::MailFromUnauthenticated => "MAIL FROM without authentication",
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

    pub fn explain(&self) -> &'static str {
        match self {
            SmtpEvent::Error => "An error occurred during an SMTP command",
            SmtpEvent::RemoteIdNotFound => {
                "The remote server ID was not found in the configuration"
            }
            SmtpEvent::ConcurrencyLimitExceeded => "The concurrency limit was exceeded",
            SmtpEvent::TransferLimitExceeded => {
                "The remote host transferred more data than allowed"
            }
            SmtpEvent::RateLimitExceeded => "The rate limit was exceeded",
            SmtpEvent::TimeLimitExceeded => "The remote host kept the SMTP session open too long",
            SmtpEvent::MissingAuthDirectory => "The auth directory was missing",
            SmtpEvent::MessageParseFailed => "Failed to parse the message",
            SmtpEvent::MessageTooLarge => "The message was rejected because it was too large",
            SmtpEvent::LoopDetected => {
                "A mail loop was detected, the message contains too many Received headers"
            }
            SmtpEvent::PipeSuccess => "The pipe command succeeded",
            SmtpEvent::PipeError => "The pipe command failed",
            SmtpEvent::DkimPass => "Successful DKIM verification",
            SmtpEvent::DkimFail => "Failed to verify DKIM signature",
            SmtpEvent::ArcPass => "Successful ARC verification",
            SmtpEvent::ArcFail => "Failed to verify ARC signature",
            SmtpEvent::SpfEhloPass => "EHLO identity passed SPF check",
            SmtpEvent::SpfEhloFail => "EHLO identity failed SPF check",
            SmtpEvent::SpfFromPass => "MAIL FROM identity passed SPF check",
            SmtpEvent::SpfFromFail => "MAIL FROM identity failed SPF check",
            SmtpEvent::DmarcPass => "Successful DMARC verification",
            SmtpEvent::DmarcFail => "Failed to verify DMARC policy",
            SmtpEvent::IprevPass => "Reverse IP check passed",
            SmtpEvent::IprevFail => "Reverse IP check failed",
            SmtpEvent::TooManyMessages => {
                "The remote server exceeded the number of messages allowed per session"
            }
            SmtpEvent::Ehlo => "The remote server sent an EHLO command",
            SmtpEvent::InvalidEhlo => "The remote server sent an invalid EHLO command",
            SmtpEvent::DidNotSayEhlo => "The remote server did not send EHLO command",
            SmtpEvent::EhloExpected => {
                "The remote server sent a LHLO command while EHLO was expected"
            }
            SmtpEvent::LhloExpected => {
                "The remote server sent an EHLO command while LHLO was expected"
            }
            SmtpEvent::MailFromUnauthenticated => {
                "The remote client did not authenticate before sending MAIL FROM"
            }
            SmtpEvent::MailFromUnauthorized => {
                "The remote client is not authorized to send mail from the given address"
            }
            SmtpEvent::MailFromRewritten => "The envelope sender address was rewritten",
            SmtpEvent::MailFromMissing => {
                "The remote client issued an RCPT TO command before MAIL FROM"
            }
            SmtpEvent::MailFrom => "The remote client sent a MAIL FROM command",
            SmtpEvent::MultipleMailFrom => "The remote client already sent a MAIL FROM command",
            SmtpEvent::MailboxDoesNotExist => "The mailbox does not exist on the server",
            SmtpEvent::RelayNotAllowed => "The server does not allow relaying",
            SmtpEvent::RcptTo => "The remote client sent an RCPT TO command",
            SmtpEvent::RcptToDuplicate => {
                "The remote client already sent an RCPT TO command for this recipient"
            }
            SmtpEvent::RcptToRewritten => "The envelope recipient address was rewritten",
            SmtpEvent::RcptToMissing => "The remote client issued a DATA command before RCPT TO",
            SmtpEvent::TooManyRecipients => {
                "The remote client exceeded the number of recipients allowed"
            }
            SmtpEvent::TooManyInvalidRcpt => {
                "The remote client exceeded the number of invalid RCPT TO commands allowed"
            }
            SmtpEvent::RawInput => "Raw SMTP input received",
            SmtpEvent::RawOutput => "Raw SMTP output sent",
            SmtpEvent::MissingLocalHostname => "The local hostname is missing in the configuration",
            SmtpEvent::Vrfy => "The remote client sent a VRFY command",
            SmtpEvent::VrfyNotFound => {
                "The remote client sent a VRFY command for an address that was not found"
            }
            SmtpEvent::VrfyDisabled => "The VRFY command is disabled",
            SmtpEvent::Expn => "The remote client sent an EXPN command",
            SmtpEvent::ExpnNotFound => {
                "The remote client sent an EXPN command for an address that was not found"
            }
            SmtpEvent::ExpnDisabled => "The EXPN command is disabled",
            SmtpEvent::RequireTlsDisabled => "The REQUIRETLS extension is disabled",
            SmtpEvent::DeliverByDisabled => "The DELIVERBY extension is disabled",
            SmtpEvent::DeliverByInvalid => "The DELIVERBY parameter is invalid",
            SmtpEvent::FutureReleaseDisabled => "The FUTURE RELEASE extension is disabled",
            SmtpEvent::FutureReleaseInvalid => "The FUTURE RELEASE parameter is invalid",
            SmtpEvent::MtPriorityDisabled => "The MT-PRIORITY extension is disabled",
            SmtpEvent::MtPriorityInvalid => "The MT-PRIORITY parameter is invalid",
            SmtpEvent::DsnDisabled => "The DSN extension is disabled",
            SmtpEvent::AuthNotAllowed => "Authentication is not allowed on this listener",
            SmtpEvent::AuthMechanismNotSupported => {
                "The requested authentication mechanism is not supported"
            }
            SmtpEvent::AuthExchangeTooLong => "The authentication exchange was too long",
            SmtpEvent::AlreadyAuthenticated => "The client is already authenticated",
            SmtpEvent::Noop => "The remote client sent a NOOP command",
            SmtpEvent::StartTls => "The remote client requested a TLS connection",
            SmtpEvent::StartTlsUnavailable => {
                "The remote client requested a TLS connection but it is not available"
            }
            SmtpEvent::Rset => "The remote client sent a RSET command",
            SmtpEvent::Quit => "The remote client sent a QUIT command",
            SmtpEvent::Help => "The remote client sent a HELP command",
            SmtpEvent::CommandNotImplemented => {
                "The server does not implement the requested command"
            }
            SmtpEvent::InvalidCommand => "The remote client sent an invalid command",
            SmtpEvent::InvalidSenderAddress => "The specified sender address is invalid",
            SmtpEvent::InvalidRecipientAddress => "The specified recipient address is invalid",
            SmtpEvent::InvalidParameter => "The command contained an invalid parameter",
            SmtpEvent::UnsupportedParameter => "The command contained an unsupported parameter",
            SmtpEvent::SyntaxError => "The command contained a syntax error",
            SmtpEvent::RequestTooLarge => "The request was too large",
            SmtpEvent::ConnectionStart => "A new SMTP connection was started",
            SmtpEvent::ConnectionEnd => "The SMTP connection was ended",
            SmtpEvent::StartTlsAlready => "TLS is already active",
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

    pub fn explain(&self) -> &'static str {
        match self {
            DeliveryEvent::AttemptStart => "A new delivery attempt for the message has started",
            DeliveryEvent::AttemptEnd => "The delivery attempt has ended",
            DeliveryEvent::Completed => "Delivery was completed for all recipients",
            DeliveryEvent::Failed => "Message delivery failed due to a temporary error",
            DeliveryEvent::DomainDeliveryStart => "A new delivery attempt for a domain has started",
            DeliveryEvent::MxLookup => "Looking up MX records for the domain",
            DeliveryEvent::MxLookupFailed => "Failed to look up MX records for the domain",
            DeliveryEvent::IpLookup => "Looking up IP address for the domain",
            DeliveryEvent::IpLookupFailed => "Failed to look up IP address for the domain",
            DeliveryEvent::NullMx => "The domain has a null MX record, delivery is impossible",
            DeliveryEvent::Connect => "Connecting to the remote server",
            DeliveryEvent::ConnectError => "Error connecting to the remote server",
            DeliveryEvent::MissingOutboundHostname => {
                "The outbound hostname is missing in the configuration"
            }
            DeliveryEvent::GreetingFailed => {
                "Failed to read the SMTP greeting from the remote server"
            }
            DeliveryEvent::Ehlo => "The EHLO command was sent to the remote server",
            DeliveryEvent::EhloRejected => "The remote server rejected the EHLO command",
            DeliveryEvent::Auth => "Authenticating with the remote server",
            DeliveryEvent::AuthFailed => "Authentication with the remote server failed",
            DeliveryEvent::MailFrom => "The MAIL FROM command was sent to the remote server",
            DeliveryEvent::MailFromRejected => "The remote server rejected the MAIL FROM command",
            DeliveryEvent::Delivered => "The message was delivered to the recipient",
            DeliveryEvent::RcptTo => "The RCPT TO command was sent to the remote server",
            DeliveryEvent::RcptToRejected => "The remote server rejected the RCPT TO command",
            DeliveryEvent::RcptToFailed => {
                "Failed to send the RCPT TO command to the remote server"
            }
            DeliveryEvent::MessageRejected => "The remote server rejected the message",
            DeliveryEvent::StartTls => "Requesting a TLS connection with the remote server",
            DeliveryEvent::StartTlsUnavailable => "The remote server does not support STARTTLS",
            DeliveryEvent::StartTlsError => "It was not possible to establish a TLS connection",
            DeliveryEvent::StartTlsDisabled => {
                "STARTTLS has been disabled in the configuration for this host"
            }
            DeliveryEvent::ImplicitTlsError => "Error starting implicit TLS",
            DeliveryEvent::ConcurrencyLimitExceeded => {
                "The concurrency limit was exceeded for the remote host"
            }
            DeliveryEvent::RateLimitExceeded => "The rate limit was exceeded for the remote host",
            DeliveryEvent::DoubleBounce => "The message was discarded after a double bounce",
            DeliveryEvent::DsnSuccess => "A success delivery status notification was created",
            DeliveryEvent::DsnTempFail => {
                "A temporary failure delivery status notification was created"
            }
            DeliveryEvent::DsnPermFail => {
                "A permanent failure delivery status notification was created"
            }
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
            QueueEvent::QueueMessageAuthenticated => "Queued message submission for delivery",
            QueueEvent::QueueReport => "Queued report for delivery",
            QueueEvent::QueueDsn => "Queued DSN for delivery",
            QueueEvent::QueueAutogenerated => "Queued autogenerated message for delivery",
        }
    }

    pub fn explain(&self) -> &'static str {
        match self {
            QueueEvent::Rescheduled => "The message was rescheduled for delivery",
            QueueEvent::LockBusy => "The queue lock is busy",
            QueueEvent::Locked => "The queue is locked",
            QueueEvent::BlobNotFound => "The message blob was not found",
            QueueEvent::RateLimitExceeded => "The queue rate limit was exceeded",
            QueueEvent::ConcurrencyLimitExceeded => "The queue concurrency limit was exceeded",
            QueueEvent::QuotaExceeded => "The queue quota was exceeded",
            QueueEvent::QueueMessage => "A new message was queued for delivery",
            QueueEvent::QueueMessageAuthenticated => {
                "A new message was queued for delivery from an authenticated client"
            }
            QueueEvent::QueueReport => "A new report was queued for delivery",
            QueueEvent::QueueDsn => "A delivery status notification was queued for delivery",
            QueueEvent::QueueAutogenerated => "A system generated message was queued for delivery",
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

    pub fn explain(&self) -> &'static str {
        match self {
            IncomingReportEvent::DmarcReport => "A DMARC report has been received",
            IncomingReportEvent::DmarcReportWithWarnings => {
                "A DMARC report with warnings has been received"
            }
            IncomingReportEvent::TlsReport => "A TLS report has been received",
            IncomingReportEvent::TlsReportWithWarnings => {
                "A TLS report with warnings has been received"
            }
            IncomingReportEvent::AbuseReport => "An abuse report has been received",
            IncomingReportEvent::AuthFailureReport => {
                "An authentication failure report has been received"
            }
            IncomingReportEvent::FraudReport => "A fraud report has been received",
            IncomingReportEvent::NotSpamReport => "A not spam report has been received",
            IncomingReportEvent::VirusReport => "A virus report has been received",
            IncomingReportEvent::OtherReport => "An unknown type of report has been received",
            IncomingReportEvent::MessageParseFailed => {
                "Failed to parse the incoming report message"
            }
            IncomingReportEvent::DmarcParseFailed => "Failed to parse the DMARC report",
            IncomingReportEvent::TlsRpcParseFailed => "Failed to parse the TLS RPC report",
            IncomingReportEvent::ArfParseFailed => "Failed to parse the ARF report",
            IncomingReportEvent::DecompressError => "Error decompressing the report",
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

    pub fn explain(&self) -> &'static str {
        match self {
            OutgoingReportEvent::SpfReport => "An SPF report has been sent",
            OutgoingReportEvent::SpfRateLimited => "The SPF report was rate limited",
            OutgoingReportEvent::DkimReport => "A DKIM report has been sent",
            OutgoingReportEvent::DkimRateLimited => "The DKIM report was rate limited",
            OutgoingReportEvent::DmarcReport => "A DMARC report has been sent",
            OutgoingReportEvent::DmarcRateLimited => "The DMARC report was rate limited",
            OutgoingReportEvent::DmarcAggregateReport => "A DMARC aggregate report has been sent",
            OutgoingReportEvent::TlsAggregate => "A TLS aggregate report has been sent",
            OutgoingReportEvent::HttpSubmission => "The report was submitted via HTTP",
            OutgoingReportEvent::UnauthorizedReportingAddress => {
                "The reporting address is not authorized to send reports"
            }
            OutgoingReportEvent::ReportingAddressValidationError => {
                "Error validating the reporting address"
            }
            OutgoingReportEvent::NotFound => "The report was not found",
            OutgoingReportEvent::SubmissionError => "Error submitting the report",
            OutgoingReportEvent::NoRecipientsFound => "No recipients found for the report",
            OutgoingReportEvent::LockBusy => "The report lock is busy",
            OutgoingReportEvent::LockDeleted => "The report lock was deleted",
            OutgoingReportEvent::Locked => "The report is locked",
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

    pub fn explain(&self) -> &'static str {
        match self {
            MtaStsEvent::Authorized => "The host is authorized by the MTA-STS policy",
            MtaStsEvent::NotAuthorized => "The host is not authorized by the MTA-STS policy",
            MtaStsEvent::PolicyFetch => "The MTA-STS policy has been fetched",
            MtaStsEvent::PolicyNotFound => "An MTA-STS policy was not found",
            MtaStsEvent::PolicyFetchError => "An error occurred while fetching the MTA-STS policy",
            MtaStsEvent::InvalidPolicy => "The MTA-STS policy is invalid",
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

    pub fn explain(&self) -> &'static str {
        match self {
            TlsRptEvent::RecordFetch => "The TLS-RPT record has been fetched",
            TlsRptEvent::RecordFetchError => "An error occurred while fetching the TLS-RPT record",
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

    pub fn explain(&self) -> &'static str {
        match self {
            DaneEvent::AuthenticationSuccess => "Successful DANE authentication",
            DaneEvent::AuthenticationFailure => "Failed DANE authentication",
            DaneEvent::NoCertificatesFound => "No certificates were found for DANE",
            DaneEvent::CertificateParseError => "An error occurred while parsing the certificate",
            DaneEvent::TlsaRecordMatch => "A TLSA record match was found",
            DaneEvent::TlsaRecordFetch => "The TLSA record has been fetched",
            DaneEvent::TlsaRecordFetchError => "An error occurred while fetching the TLSA record",
            DaneEvent::TlsaRecordNotFound => "The TLSA record was not found",
            DaneEvent::TlsaRecordNotDnssecSigned => "The TLSA record is not DNSSEC signed",
            DaneEvent::TlsaRecordInvalid => "The TLSA record is invalid",
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

    pub fn explain(&self) -> &'static str {
        match self {
            MilterEvent::Read => "Reading from the Milter",
            MilterEvent::Write => "Writing to the Milter",
            MilterEvent::ActionAccept => "The Milter requested to accept the message",
            MilterEvent::ActionDiscard => "The Milter requested to discard the message",
            MilterEvent::ActionReject => "The Milter requested to reject the message",
            MilterEvent::ActionTempFail => "The Milter requested to temporarily fail the message",
            MilterEvent::ActionReplyCode => "The Milter requested a reply code",
            MilterEvent::ActionConnectionFailure => "The Milter requested a connection failure",
            MilterEvent::ActionShutdown => "The Milter requested a shutdown",
            MilterEvent::IoError => "An I/O error occurred with the Milter",
            MilterEvent::FrameTooLarge => "The Milter frame was too large",
            MilterEvent::FrameInvalid => "The Milter frame was invalid",
            MilterEvent::UnexpectedResponse => {
                "An unexpected response was received from the Milter"
            }
            MilterEvent::Timeout => "A timeout occurred with the Milter",
            MilterEvent::TlsInvalidName => "The Milter TLS name is invalid",
            MilterEvent::Disconnected => "The Milter disconnected",
            MilterEvent::ParseError => "An error occurred while parsing the Milter response",
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

    pub fn explain(&self) -> &'static str {
        match self {
            MtaHookEvent::ActionAccept => "The MTA hook requested to accept the message",
            MtaHookEvent::ActionDiscard => "The MTA hook requested to discard the message",
            MtaHookEvent::ActionReject => "The MTA hook requested to reject the message",
            MtaHookEvent::ActionQuarantine => "The MTA hook requested to quarantine the message",
            MtaHookEvent::Error => "An error occurred with the MTA hook",
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

    pub fn explain(&self) -> &'static str {
        match self {
            PushSubscriptionEvent::Success => "The push subscription was successful",
            PushSubscriptionEvent::Error => "An error occurred with the push subscription",
            PushSubscriptionEvent::NotFound => "The push subscription was not found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            SpamEvent::PyzorError => "An error occurred with Pyzor",
            SpamEvent::ListUpdated => "The spam list has been updated",
            SpamEvent::Train => "The spam filter is being trained with the message",
            SpamEvent::TrainBalance => "The spam filter training data is being balanced",
            SpamEvent::TrainError => "An error occurred while training the spam filter",
            SpamEvent::Classify => "The message is being classified for spam",
            SpamEvent::ClassifyError => "An error occurred while classifying the message for spam",
            SpamEvent::NotEnoughTrainingData => {
                "There is not enough training data for the spam filter"
            }
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

    pub fn explain(&self) -> &'static str {
        match self {
            SieveEvent::ActionAccept => "The Sieve script requested to accept the message",
            SieveEvent::ActionAcceptReplace => {
                "The Sieve script requested to accept the message and replace its contents"
            }
            SieveEvent::ActionDiscard => "The Sieve script requested to discard the message",
            SieveEvent::ActionReject => "The Sieve script requested to reject the message",
            SieveEvent::SendMessage => "The Sieve script is sending a message",
            SieveEvent::MessageTooLarge => "The Sieve message is too large",
            SieveEvent::ScriptNotFound => "The Sieve script was not found",
            SieveEvent::ListNotFound => "The Sieve list was not found",
            SieveEvent::RuntimeError => "A runtime error occurred with the Sieve script",
            SieveEvent::UnexpectedError => "An unexpected error occurred with the Sieve script",
            SieveEvent::NotSupported => "The Sieve action is not supported",
            SieveEvent::QuotaExceeded => "The Sieve quota was exceeded",
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

    pub fn explain(&self) -> &'static str {
        match self {
            TlsEvent::Handshake => "Successful TLS handshake",
            TlsEvent::HandshakeError => "An error occurred during the TLS handshake",
            TlsEvent::NotConfigured => "TLS is not configured",
            TlsEvent::CertificateNotFound => "The TLS certificate was not found",
            TlsEvent::NoCertificatesAvailable => "No TLS certificates are available",
            TlsEvent::MultipleCertificatesAvailable => "Multiple TLS certificates are available",
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

    pub fn explain(&self) -> &'static str {
        match self {
            NetworkEvent::ListenStart => "The network listener has started",
            NetworkEvent::ListenStop => "The network listener has stopped",
            NetworkEvent::ListenError => "An error occurred with the network listener",
            NetworkEvent::BindError => "An error occurred while binding the network listener",
            NetworkEvent::ReadError => "An error occurred while reading from the network",
            NetworkEvent::WriteError => "An error occurred while writing to the network",
            NetworkEvent::FlushError => "An error occurred while flushing the network",
            NetworkEvent::AcceptError => "An error occurred while accepting a network connection",
            NetworkEvent::SplitError => "An error occurred while splitting the network connection",
            NetworkEvent::Timeout => "A network timeout occurred",
            NetworkEvent::Closed => "The network connection was closed",
            NetworkEvent::ProxyError => "An error occurred with the proxy protocol",
            NetworkEvent::SetOptError => "An error occurred while setting network options",
            NetworkEvent::DropBlocked => "The connection was dropped from a blocked IP address",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ServerEvent::Startup => "Stalwart Mail Server has started",
            ServerEvent::Shutdown => "Stalwart Mail Server is shutting down",
            ServerEvent::StartupError => "An error occurred while starting the server",
            ServerEvent::ThreadError => "An error occurred with a server thread",
            ServerEvent::Licensing => "A licensing event occurred",
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

    pub fn explain(&self) -> &'static str {
        match self {
            TelemetryEvent::LogError => "An error occurred with the log collector",
            TelemetryEvent::WebhookError => "An error occurred with the webhook collector",
            TelemetryEvent::JournalError => "An error occurred with the journal collector",
            TelemetryEvent::OtelExporterError => {
                "An error occurred with the OpenTelemetry exporter"
            }
            TelemetryEvent::OtelMetricsExporterError => {
                "An error occurred with the OpenTelemetry metrics exporter"
            }
            TelemetryEvent::PrometheusExporterError => {
                "An error occurred with the Prometheus exporter"
            }
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

    pub fn explain(&self) -> &'static str {
        match self {
            AcmeEvent::AuthStart => "ACME authentication has started",
            AcmeEvent::AuthPending => "ACME authentication is pending",
            AcmeEvent::AuthValid => "ACME authentication is valid",
            AcmeEvent::AuthCompleted => "ACME authentication has completed",
            AcmeEvent::AuthError => "An error occurred with ACME authentication",
            AcmeEvent::AuthTooManyAttempts => "Too many ACME authentication attempts",
            AcmeEvent::ProcessCert => "Processing the ACME certificate",
            AcmeEvent::OrderStart => "ACME order has started",
            AcmeEvent::OrderProcessing => "ACME order is processing",
            AcmeEvent::OrderCompleted => "ACME order has completed",
            AcmeEvent::OrderReady => "ACME order is ready",
            AcmeEvent::OrderValid => "ACME order is valid",
            AcmeEvent::OrderInvalid => "ACME order is invalid",
            AcmeEvent::RenewBackoff => "ACME renew backoff",
            AcmeEvent::DnsRecordCreated => "ACME DNS record has been created",
            AcmeEvent::DnsRecordCreationFailed => "Failed to create ACME DNS record",
            AcmeEvent::DnsRecordDeletionFailed => "Failed to delete ACME DNS record",
            AcmeEvent::DnsRecordNotPropagated => "ACME DNS record has not propagated",
            AcmeEvent::DnsRecordLookupFailed => "Failed to look up ACME DNS record",
            AcmeEvent::DnsRecordPropagated => "ACME DNS record has propagated",
            AcmeEvent::DnsRecordPropagationTimeout => "ACME DNS record propagation timeout",
            AcmeEvent::ClientSuppliedSni => "ACME client supplied SNI",
            AcmeEvent::ClientMissingSni => "ACME client missing SNI",
            AcmeEvent::TlsAlpnReceived => "ACME TLS ALPN received",
            AcmeEvent::TlsAlpnError => "ACME TLS ALPN error",
            AcmeEvent::TokenNotFound => "ACME token not found",
            AcmeEvent::Error => "An error occurred with ACME",
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

    pub fn explain(&self) -> &'static str {
        match self {
            PurgeEvent::Started => "The purge has started",
            PurgeEvent::Finished => "The purge has finished",
            PurgeEvent::Running => "The purge is running",
            PurgeEvent::Error => "An error occurred with the purge",
            PurgeEvent::PurgeActive => "An active purge is in progress",
            PurgeEvent::AutoExpunge => "Auto-expunge has been executed",
            PurgeEvent::TombstoneCleanup => "Tombstone cleanup has been executed",
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

    pub fn explain(&self) -> &'static str {
        match self {
            EvalEvent::Result => "The expression evaluation has a result",
            EvalEvent::Error => "An error occurred while evaluating the expression",
            EvalEvent::DirectoryNotFound => {
                "The directory was not found while evaluating the expression"
            }
            EvalEvent::StoreNotFound => "The store was not found while evaluating the expression",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ConfigEvent::ParseError => "An error occurred while parsing the configuration",
            ConfigEvent::BuildError => "An error occurred while building the configuration",
            ConfigEvent::MacroError => "An error occurred with a configuration macro",
            ConfigEvent::WriteError => "An error occurred while writing the configuration",
            ConfigEvent::FetchError => "An error occurred while fetching the configuration",
            ConfigEvent::DefaultApplied => "The default configuration has been applied",
            ConfigEvent::MissingSetting => "A configuration setting is missing",
            ConfigEvent::UnusedSetting => "A configuration setting is unused",
            ConfigEvent::ParseWarning => "A warning occurred while parsing the configuration",
            ConfigEvent::BuildWarning => "A warning occurred while building the configuration",
            ConfigEvent::ImportExternal => "An external configuration is being imported",
            ConfigEvent::ExternalKeyIgnored => "An external configuration key is ignored",
            ConfigEvent::AlreadyUpToDate => "The configuration is already up to date",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ArcEvent::ChainTooLong => "The ARC chain is too long",
            ArcEvent::InvalidInstance => "The ARC instance is invalid",
            ArcEvent::InvalidCv => "The ARC CV is invalid",
            ArcEvent::HasHeaderTag => "The ARC has a header tag",
            ArcEvent::BrokenChain => "The ARC chain is broken",
            ArcEvent::SealerNotFound => "The ARC sealer was not found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            DkimEvent::Pass => "DKIM verification has passed",
            DkimEvent::Neutral => "DKIM verification is neutral",
            DkimEvent::Fail => "DKIM verification has failed",
            DkimEvent::PermError => "A permanent error occurred with DKIM",
            DkimEvent::TempError => "A temporary error occurred with DKIM",
            DkimEvent::None => "No DKIM signature was found",
            DkimEvent::UnsupportedVersion => "The DKIM version is unsupported",
            DkimEvent::UnsupportedAlgorithm => "The DKIM algorithm is unsupported",
            DkimEvent::UnsupportedCanonicalization => "The DKIM canonicalization is unsupported",
            DkimEvent::UnsupportedKeyType => "The DKIM key type is unsupported",
            DkimEvent::FailedBodyHashMatch => "The DKIM body hash does not match",
            DkimEvent::FailedVerification => "The DKIM verification has failed",
            DkimEvent::FailedAuidMatch => "The DKIM AUID does not match",
            DkimEvent::RevokedPublicKey => "The DKIM public key has been revoked",
            DkimEvent::IncompatibleAlgorithms => "The DKIM algorithms are incompatible",
            DkimEvent::SignatureExpired => "The DKIM signature has expired",
            DkimEvent::SignatureLength => "The DKIM signature length is incorrect",
            DkimEvent::SignerNotFound => "The DKIM signer was not found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            SpfEvent::Pass => "The SPF check has passed",
            SpfEvent::Fail => "The SPF check has failed",
            SpfEvent::SoftFail => "The SPF check has soft failed",
            SpfEvent::Neutral => "The SPF result is neutral",
            SpfEvent::TempError => "A temporary error occurred with SPF",
            SpfEvent::PermError => "A permanent error occurred with SPF",
            SpfEvent::None => "No SPF record was found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            DmarcEvent::Pass => "The DMARC check has passed",
            DmarcEvent::Fail => "The DMARC check has failed",
            DmarcEvent::PermError => "A permanent error occurred with DMARC",
            DmarcEvent::TempError => "A temporary error occurred with DMARC",
            DmarcEvent::None => "No DMARC record was found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            IprevEvent::Pass => "The IPREV check has passed",
            IprevEvent::Fail => "The IPREV check has failed",
            IprevEvent::PermError => "A permanent error occurred with IPREV",
            IprevEvent::TempError => "A temporary error occurred with IPREV",
            IprevEvent::None => "No IPREV record was found",
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

    pub fn explain(&self) -> &'static str {
        match self {
            MailAuthEvent::ParseError => "An error occurred while parsing mail authentication",
            MailAuthEvent::MissingParameters => "Mail authentication parameters are missing",
            MailAuthEvent::NoHeadersFound => "No headers were found in the message",
            MailAuthEvent::Crypto => "A crypto error occurred during mail authentication",
            MailAuthEvent::Io => "An I/O error occurred during mail authentication",
            MailAuthEvent::Base64 => "A base64 error occurred during mail authentication",
            MailAuthEvent::DnsError => "A DNS error occurred",
            MailAuthEvent::DnsRecordNotFound => "The DNS record was not found",
            MailAuthEvent::DnsInvalidRecordType => "The DNS record type is invalid",
            MailAuthEvent::PolicyNotAligned => "The policy is not aligned",
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

    pub fn explain(&self) -> &'static str {
        match self {
            StoreEvent::AssertValueFailed => "Another process modified the record",
            StoreEvent::FoundationdbError => "A FoundationDB error occurred",
            StoreEvent::MysqlError => "A MySQL error occurred",
            StoreEvent::PostgresqlError => "A PostgreSQL error occurred",
            StoreEvent::RocksdbError => "A RocksDB error occurred",
            StoreEvent::SqliteError => "An SQLite error occurred",
            StoreEvent::LdapError => "An LDAP error occurred",
            StoreEvent::ElasticsearchError => "An ElasticSearch error occurred",
            StoreEvent::RedisError => "A Redis error occurred",
            StoreEvent::S3Error => "An S3 error occurred",
            StoreEvent::FilesystemError => "A filesystem error occurred",
            StoreEvent::PoolError => "A connection pool error occurred",
            StoreEvent::DataCorruption => "Data corruption was detected",
            StoreEvent::DecompressError => "A decompression error occurred",
            StoreEvent::DeserializeError => "A deserialization error occurred",
            StoreEvent::NotFound => "The record was not found in the database",
            StoreEvent::NotConfigured => "The store is not configured",
            StoreEvent::NotSupported => "The operation is not supported by the store",
            StoreEvent::UnexpectedError => "An unexpected store error occurred",
            StoreEvent::CryptoError => "A store crypto error occurred",
            StoreEvent::BlobMissingMarker => "The blob is missing a marker",
            StoreEvent::SqlQuery => "An SQL query was executed",
            StoreEvent::LdapQuery => "An LDAP query was executed",
            StoreEvent::LdapBind => "An LDAP bind operation was executed",
            StoreEvent::DataWrite => "A write batch operation was executed",
            StoreEvent::BlobRead => "A blob read operation was executed",
            StoreEvent::BlobWrite => "A blob write operation was executed",
            StoreEvent::BlobDelete => "A blob delete operation was executed",
            StoreEvent::DataIterate => "A data store iteration operation was executed",
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

    pub fn explain(&self) -> &'static str {
        match self {
            MessageIngestEvent::Ham => "The message has been ingested",
            MessageIngestEvent::Spam => "A possible spam message has been ingested",
            MessageIngestEvent::ImapAppend => "The message has been appended via IMAP",
            MessageIngestEvent::JmapAppend => "The message has been appended via JMAP",
            MessageIngestEvent::Duplicate => "The message is a duplicate and has been skipped",
            MessageIngestEvent::Error => "An error occurred while ingesting the message",
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

    pub fn explain(&self) -> &'static str {
        match self {
            JmapEvent::MethodCall => "A JMAP method call has been made",
            JmapEvent::InvalidArguments => "The JMAP arguments are invalid",
            JmapEvent::RequestTooLarge => "The JMAP request is too large",
            JmapEvent::StateMismatch => "The JMAP state is mismatched",
            JmapEvent::AnchorNotFound => "The JMAP anchor was not found",
            JmapEvent::UnsupportedFilter => "The JMAP filter is unsupported",
            JmapEvent::UnsupportedSort => "The JMAP sort is unsupported",
            JmapEvent::UnknownMethod => "The JMAP method is unknown",
            JmapEvent::InvalidResultReference => "The JMAP result reference is invalid",
            JmapEvent::Forbidden => "The JMAP operation is forbidden",
            JmapEvent::AccountNotFound => "The JMAP account was not found",
            JmapEvent::AccountNotSupportedByMethod => {
                "The JMAP account is not supported by the method"
            }
            JmapEvent::AccountReadOnly => "The JMAP account is read-only",
            JmapEvent::NotFound => "The JMAP resource was not found",
            JmapEvent::CannotCalculateChanges => "Cannot calculate JMAP changes",
            JmapEvent::UnknownDataType => "The JMAP data type is unknown",
            JmapEvent::UnknownCapability => "The JMAP capability is unknown",
            JmapEvent::NotJson => "The JMAP request is not JSON",
            JmapEvent::NotRequest => "The JMAP input is not a request",
            JmapEvent::WebsocketStart => "The JMAP WebSocket connection has started",
            JmapEvent::WebsocketStop => "The JMAP WebSocket connection has stopped",
            JmapEvent::WebsocketError => "An error occurred with the JMAP WebSocket connection",
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

    pub fn explain(&self) -> &'static str {
        match self {
            LimitEvent::SizeRequest => "The request size limit has been reached",
            LimitEvent::SizeUpload => "The upload size limit has been reached",
            LimitEvent::CallsIn => "The incoming calls limit has been reached",
            LimitEvent::ConcurrentRequest => "The concurrent request limit has been reached",
            LimitEvent::ConcurrentUpload => "The concurrent upload limit has been reached",
            LimitEvent::ConcurrentConnection => "The concurrent connection limit has been reached",
            LimitEvent::Quota => "The quota limit has been reached",
            LimitEvent::BlobQuota => "The blob quota limit has been reached",
            LimitEvent::TooManyRequests => "Too many requests have been made",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ManageEvent::MissingParameter => "A management parameter is missing",
            ManageEvent::AlreadyExists => "The managed resource already exists",
            ManageEvent::AssertFailed => "A management assertion has failed",
            ManageEvent::NotFound => "The managed resource was not found",
            ManageEvent::NotSupported => "The management operation is not supported",
            ManageEvent::Error => "A management error occurred",
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

    pub fn explain(&self) -> &'static str {
        match self {
            AuthEvent::Success => "Successful authentication",
            AuthEvent::Failed => "Failed authentication",
            AuthEvent::MissingTotp => "TOTP is missing for authentication",
            AuthEvent::TooManyAttempts => "Too many authentication attempts have been made",
            AuthEvent::Banned => {
                "The IP address has been banned after multiple authentication failures"
            }
            AuthEvent::Error => "An error occurred with authentication",
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

    pub fn explain(&self) -> &'static str {
        match self {
            ResourceEvent::NotFound => "The resource was not found",
            ResourceEvent::BadParameters => "The resource parameters are bad",
            ResourceEvent::Error => "An error occurred with the resource",
            ResourceEvent::DownloadExternal => "The external resource is being downloaded",
            ResourceEvent::WebadminUnpacked => "The webadmin resource has been unpacked",
        }
    }
}
