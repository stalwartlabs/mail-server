/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use atomics::{array::AtomicU32Array, gauge::AtomicGauge, histogram::AtomicHistogram};
use ipc::{
    collector::{Collector, GlobalInterests, EVENT_TYPES},
    subscriber::Interests,
};

use crate::*;

pub(crate) static METRIC_INTERESTS: GlobalInterests = GlobalInterests::new();

static EVENT_COUNTERS: AtomicU32Array<TOTAL_EVENT_COUNT> = AtomicU32Array::new();
static CONNECTION_METRICS: [ConnectionMetrics; TOTAL_CONN_TYPES] = init_conn_metrics();

static MESSAGE_INGESTION_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::MessageIngestionTime);
static MESSAGE_INDEX_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::MessageFtsIndexTime);
static MESSAGE_DELIVERY_TIME: AtomicHistogram<12> =
    AtomicHistogram::<18>::new_long_durations(MetricType::DeliveryTotalTime);

static MESSAGE_INCOMING_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::MessageSize);
static MESSAGE_SUBMISSION_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::MessageAuthSize);
static MESSAGE_OUT_REPORT_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes(MetricType::ReportOutgoingSize);

static STORE_DATA_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreReadTime);
static STORE_DATA_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::StoreWriteTime);
static STORE_BLOB_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::BlobReadTime);
static STORE_BLOB_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::BlobWriteTime);

static DNS_LOOKUP_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations(MetricType::DnsLookupTime);

static SERVER_MEMORY: AtomicGauge = AtomicGauge::new(MetricType::ServerMemory);
static QUEUE_COUNT: AtomicGauge = AtomicGauge::new(MetricType::QueueCount);
static USER_COUNT: AtomicGauge = AtomicGauge::new(MetricType::UserCount);
static DOMAIN_COUNT: AtomicGauge = AtomicGauge::new(MetricType::DomainCount);

const CONN_SMTP_IN: usize = 0;
const CONN_SMTP_OUT: usize = 1;
const CONN_IMAP: usize = 2;
const CONN_POP3: usize = 3;
const CONN_HTTP: usize = 4;
const CONN_SIEVE: usize = 5;
const TOTAL_CONN_TYPES: usize = 6;

pub struct ConnectionMetrics {
    pub active_connections: AtomicGauge,
    pub elapsed: AtomicHistogram<12>,
}

pub struct EventCounter {
    id: EventType,
    value: u32,
}

impl Collector {
    pub fn record_metric(event: EventType, event_id: usize, keys: &[(Key, Value)]) {
        // Increment the event counter
        if !event.is_span_end() && !event.is_raw_io() {
            EVENT_COUNTERS.add(event_id, 1);
        }

        // Extract variables
        let mut elapsed = 0;
        let mut size = 0;
        for (key, value) in keys {
            match (key, value) {
                (Key::Elapsed, Value::Duration(d)) => elapsed = *d,
                (Key::Size, Value::UInt(s)) => size = *s,
                _ => {}
            }
        }

        match event {
            EventType::Smtp(SmtpEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_IN];
                conn.active_connections.increment();
            }
            EventType::Smtp(SmtpEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_IN];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Imap(ImapEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_IMAP];
                conn.active_connections.increment();
            }
            EventType::Imap(ImapEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_IMAP];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Pop3(Pop3Event::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_POP3];
                conn.active_connections.increment();
            }
            EventType::Pop3(Pop3Event::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_POP3];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Http(HttpEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_HTTP];
                conn.active_connections.increment();
            }
            EventType::Http(HttpEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_HTTP];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[CONN_SIEVE];
                conn.active_connections.increment();
            }
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SIEVE];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::AttemptStart) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.active_connections.increment();
            }
            EventType::Delivery(DeliveryEvent::AttemptEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::Completed) => {
                QUEUE_COUNT.decrement();
                MESSAGE_DELIVERY_TIME.observe(elapsed);
            }
            EventType::Delivery(
                DeliveryEvent::MxLookup | DeliveryEvent::IpLookup | DeliveryEvent::NullMx,
            )
            | EventType::TlsRpt(_)
            | EventType::MtaSts(_)
            | EventType::Dane(_) => {
                if elapsed > 0 {
                    DNS_LOOKUP_TIME.observe(elapsed);
                }
            }
            EventType::MessageIngest(
                MessageIngestEvent::Ham
                | MessageIngestEvent::Spam
                | MessageIngestEvent::ImapAppend
                | MessageIngestEvent::JmapAppend,
            ) => {
                MESSAGE_INGESTION_TIME.observe(elapsed);
            }
            EventType::Queue(QueueEvent::QueueMessage) => {
                MESSAGE_INCOMING_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueMessageAuthenticated) => {
                MESSAGE_SUBMISSION_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueReport) => {
                MESSAGE_OUT_REPORT_SIZE.observe(size);
                QUEUE_COUNT.increment();
            }
            EventType::Queue(QueueEvent::QueueAutogenerated | QueueEvent::QueueDsn) => {
                QUEUE_COUNT.increment();
            }
            EventType::FtsIndex(FtsIndexEvent::Index) => {
                MESSAGE_INDEX_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::BlobWrite) => {
                STORE_BLOB_WRITE_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::BlobRead) => {
                STORE_BLOB_READ_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::DataWrite) => {
                STORE_DATA_WRITE_TIME.observe(elapsed);
            }
            EventType::Store(StoreEvent::DataIterate) => {
                STORE_DATA_READ_TIME.observe(elapsed);
            }

            _ => {}
        }
    }

    #[inline(always)]
    pub fn is_metric(event: impl Into<usize>) -> bool {
        METRIC_INTERESTS.get(event)
    }

    pub fn set_metrics(interests: Interests) {
        METRIC_INTERESTS.update(interests);
    }

    pub fn collect_counters(_is_enterprise: bool) -> impl Iterator<Item = EventCounter> {
        EVENT_COUNTERS
            .inner()
            .iter()
            .enumerate()
            .filter_map(|(event_id, value)| {
                let value = value.load(Ordering::Relaxed);
                if value > 0 {
                    Some(EventCounter {
                        id: EVENT_TYPES[event_id],
                        value,
                    })
                } else {
                    None
                }
            })
    }

    pub fn collect_gauges(is_enterprise: bool) -> impl Iterator<Item = &'static AtomicGauge> {
        static E_GAUGES: &[&AtomicGauge] =
            &[&SERVER_MEMORY, &QUEUE_COUNT, &USER_COUNT, &DOMAIN_COUNT];
        static C_GAUGES: &[&AtomicGauge] = &[&SERVER_MEMORY, &USER_COUNT, &DOMAIN_COUNT];

        if is_enterprise { E_GAUGES } else { C_GAUGES }
            .iter()
            .copied()
            .chain(CONNECTION_METRICS.iter().map(|m| &m.active_connections))
    }

    pub fn collect_histograms(
        is_enterprise: bool,
    ) -> impl Iterator<Item = &'static AtomicHistogram<12>> {
        static E_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_INGESTION_TIME,
            &MESSAGE_INDEX_TIME,
            &MESSAGE_DELIVERY_TIME,
            &MESSAGE_INCOMING_SIZE,
            &MESSAGE_SUBMISSION_SIZE,
            &MESSAGE_OUT_REPORT_SIZE,
            &STORE_DATA_READ_TIME,
            &STORE_DATA_WRITE_TIME,
            &STORE_BLOB_READ_TIME,
            &STORE_BLOB_WRITE_TIME,
            &DNS_LOOKUP_TIME,
        ];
        static C_HISTOGRAMS: &[&AtomicHistogram<12>] = &[
            &MESSAGE_DELIVERY_TIME,
            &MESSAGE_INCOMING_SIZE,
            &MESSAGE_SUBMISSION_SIZE,
        ];

        if is_enterprise {
            E_HISTOGRAMS
        } else {
            C_HISTOGRAMS
        }
        .iter()
        .copied()
        .chain(CONNECTION_METRICS.iter().map(|m| &m.elapsed))
        .filter(|h| h.is_active())
    }

    #[inline(always)]
    pub fn read_event_metric(metric_id: usize) -> u32 {
        EVENT_COUNTERS.get(metric_id)
    }

    pub fn read_metric(metric_type: MetricType) -> f64 {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.get() as f64,
            MetricType::MessageIngestionTime => MESSAGE_INGESTION_TIME.average(),
            MetricType::MessageFtsIndexTime => MESSAGE_INDEX_TIME.average(),
            MetricType::MessageSize => MESSAGE_INCOMING_SIZE.average(),
            MetricType::MessageAuthSize => MESSAGE_SUBMISSION_SIZE.average(),
            MetricType::DeliveryTotalTime => MESSAGE_DELIVERY_TIME.average(),
            MetricType::DeliveryTime => CONNECTION_METRICS[CONN_SMTP_OUT].elapsed.average(),
            MetricType::DeliveryActiveConnections => {
                CONNECTION_METRICS[CONN_SMTP_OUT].active_connections.get() as f64
            }
            MetricType::QueueCount => QUEUE_COUNT.get() as f64,
            MetricType::ReportOutgoingSize => MESSAGE_OUT_REPORT_SIZE.average(),
            MetricType::StoreReadTime => STORE_DATA_READ_TIME.average(),
            MetricType::StoreWriteTime => STORE_DATA_WRITE_TIME.average(),
            MetricType::BlobReadTime => STORE_BLOB_READ_TIME.average(),
            MetricType::BlobWriteTime => STORE_BLOB_WRITE_TIME.average(),
            MetricType::DnsLookupTime => DNS_LOOKUP_TIME.average(),
            MetricType::HttpActiveConnections => {
                CONNECTION_METRICS[CONN_HTTP].active_connections.get() as f64
            }
            MetricType::HttpRequestTime => CONNECTION_METRICS[CONN_HTTP].elapsed.average(),
            MetricType::ImapActiveConnections => {
                CONNECTION_METRICS[CONN_IMAP].active_connections.get() as f64
            }
            MetricType::ImapRequestTime => CONNECTION_METRICS[CONN_IMAP].elapsed.average(),
            MetricType::Pop3ActiveConnections => {
                CONNECTION_METRICS[CONN_POP3].active_connections.get() as f64
            }
            MetricType::Pop3RequestTime => CONNECTION_METRICS[CONN_POP3].elapsed.average(),
            MetricType::SmtpActiveConnections => {
                CONNECTION_METRICS[CONN_SMTP_IN].active_connections.get() as f64
            }
            MetricType::SmtpRequestTime => CONNECTION_METRICS[CONN_SMTP_IN].elapsed.average(),
            MetricType::SieveActiveConnections => {
                CONNECTION_METRICS[CONN_SIEVE].active_connections.get() as f64
            }
            MetricType::SieveRequestTime => CONNECTION_METRICS[CONN_SIEVE].elapsed.average(),
            MetricType::UserCount => USER_COUNT.get() as f64,
            MetricType::DomainCount => DOMAIN_COUNT.get() as f64,
        }
    }

    pub fn update_gauge(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::ServerMemory => SERVER_MEMORY.set(value),
            MetricType::QueueCount => QUEUE_COUNT.set(value),
            MetricType::UserCount => USER_COUNT.set(value),
            MetricType::DomainCount => DOMAIN_COUNT.set(value),
            _ => {}
        }
    }

    pub fn update_event_counter(event_type: EventType, value: u32) {
        EVENT_COUNTERS.add(event_type.into(), value);
    }

    pub fn update_histogram(metric_type: MetricType, value: u64) {
        match metric_type {
            MetricType::MessageIngestionTime => MESSAGE_INGESTION_TIME.observe(value),
            MetricType::MessageFtsIndexTime => MESSAGE_INDEX_TIME.observe(value),
            MetricType::DeliveryTotalTime => MESSAGE_DELIVERY_TIME.observe(value),
            MetricType::DeliveryTime => CONNECTION_METRICS[CONN_SMTP_OUT].elapsed.observe(value),
            MetricType::DnsLookupTime => DNS_LOOKUP_TIME.observe(value),
            _ => {}
        }
    }
}

impl EventCounter {
    pub fn id(&self) -> EventType {
        self.id
    }

    pub fn value(&self) -> u64 {
        self.value as u64
    }
}

impl ConnectionMetrics {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            active_connections: AtomicGauge::new(MetricType::BlobReadTime),
            elapsed: AtomicHistogram::<18>::new_medium_durations(MetricType::BlobReadTime),
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const fn init_conn_metrics() -> [ConnectionMetrics; TOTAL_CONN_TYPES] {
    const INIT: ConnectionMetrics = ConnectionMetrics::new();
    let mut array = [INIT; TOTAL_CONN_TYPES];
    let mut i = 0;
    while i < TOTAL_CONN_TYPES {
        let metric = match i {
            CONN_HTTP => &[
                MetricType::HttpRequestTime,
                MetricType::HttpActiveConnections,
            ],
            CONN_IMAP => &[
                MetricType::ImapRequestTime,
                MetricType::ImapActiveConnections,
            ],
            CONN_POP3 => &[
                MetricType::Pop3RequestTime,
                MetricType::Pop3ActiveConnections,
            ],
            CONN_SMTP_IN => &[
                MetricType::SmtpRequestTime,
                MetricType::SmtpActiveConnections,
            ],
            CONN_SMTP_OUT => &[
                MetricType::DeliveryTime,
                MetricType::DeliveryActiveConnections,
            ],
            CONN_SIEVE => &[
                MetricType::SieveRequestTime,
                MetricType::SieveActiveConnections,
            ],
            _ => &[MetricType::BlobReadTime, MetricType::BlobReadTime],
        };

        array[i] = ConnectionMetrics {
            elapsed: AtomicHistogram::<18>::new_medium_durations(metric[0]),
            active_connections: AtomicGauge::new(metric[1]),
        };
        i += 1;
    }
    array
}

impl EventType {
    pub fn is_metric(&self) -> bool {
        match self {
            EventType::Server(ServerEvent::ThreadError) => true,
            EventType::Purge(PurgeEvent::Error) => true,
            EventType::Eval(
                EvalEvent::Error | EvalEvent::StoreNotFound | EvalEvent::DirectoryNotFound,
            ) => true,
            EventType::Acme(
                AcmeEvent::TlsAlpnError
                | AcmeEvent::OrderCompleted
                | AcmeEvent::AuthError
                | AcmeEvent::AuthTooManyAttempts
                | AcmeEvent::DnsRecordCreationFailed
                | AcmeEvent::DnsRecordDeletionFailed
                | AcmeEvent::DnsRecordPropagationTimeout
                | AcmeEvent::ClientMissingSni
                | AcmeEvent::TokenNotFound
                | AcmeEvent::DnsRecordLookupFailed
                | AcmeEvent::OrderInvalid
                | AcmeEvent::Error,
            ) => true,
            EventType::Store(
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
                | StoreEvent::NotFound
                | StoreEvent::NotConfigured
                | StoreEvent::NotSupported
                | StoreEvent::UnexpectedError
                | StoreEvent::CryptoError
                | StoreEvent::BlobMissingMarker
                | StoreEvent::DataWrite
                | StoreEvent::DataIterate
                | StoreEvent::BlobRead
                | StoreEvent::BlobWrite
                | StoreEvent::BlobDelete,
            ) => true,
            EventType::MessageIngest(_) => true,
            EventType::Jmap(
                JmapEvent::MethodCall
                | JmapEvent::WebsocketStart
                | JmapEvent::WebsocketError
                | JmapEvent::UnsupportedFilter
                | JmapEvent::UnsupportedSort
                | JmapEvent::Forbidden
                | JmapEvent::NotJson
                | JmapEvent::NotRequest
                | JmapEvent::InvalidArguments
                | JmapEvent::RequestTooLarge
                | JmapEvent::UnknownMethod,
            ) => true,
            EventType::Imap(ImapEvent::ConnectionStart | ImapEvent::ConnectionEnd) => true,
            EventType::ManageSieve(
                ManageSieveEvent::ConnectionStart | ManageSieveEvent::ConnectionEnd,
            ) => true,
            EventType::Pop3(Pop3Event::ConnectionStart | Pop3Event::ConnectionEnd) => true,
            EventType::Smtp(
                SmtpEvent::ConnectionStart
                | SmtpEvent::ConnectionEnd
                | SmtpEvent::Error
                | SmtpEvent::ConcurrencyLimitExceeded
                | SmtpEvent::TransferLimitExceeded
                | SmtpEvent::RateLimitExceeded
                | SmtpEvent::TimeLimitExceeded
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
                | SmtpEvent::InvalidEhlo
                | SmtpEvent::DidNotSayEhlo
                | SmtpEvent::MailFromUnauthenticated
                | SmtpEvent::MailFromUnauthorized
                | SmtpEvent::MailFromMissing
                | SmtpEvent::MultipleMailFrom
                | SmtpEvent::MailboxDoesNotExist
                | SmtpEvent::RelayNotAllowed
                | SmtpEvent::RcptToDuplicate
                | SmtpEvent::RcptToMissing
                | SmtpEvent::TooManyRecipients
                | SmtpEvent::TooManyInvalidRcpt
                | SmtpEvent::AuthMechanismNotSupported
                | SmtpEvent::AuthExchangeTooLong
                | SmtpEvent::CommandNotImplemented
                | SmtpEvent::InvalidCommand
                | SmtpEvent::SyntaxError
                | SmtpEvent::RequestTooLarge,
            ) => true,
            EventType::Http(
                HttpEvent::Error
                | HttpEvent::RequestBody
                | HttpEvent::ResponseBody
                | HttpEvent::XForwardedMissing,
            ) => true,
            EventType::Network(NetworkEvent::Timeout) => true,
            EventType::Security(_) => true,
            EventType::Limit(_) => true,
            EventType::Manage(_) => false,
            EventType::Auth(
                AuthEvent::Success
                | AuthEvent::Failed
                | AuthEvent::TooManyAttempts
                | AuthEvent::Error,
            ) => true,
            EventType::Config(_) => false,
            EventType::Resource(
                ResourceEvent::NotFound | ResourceEvent::BadParameters | ResourceEvent::Error,
            ) => true,
            EventType::Arc(
                ArcEvent::ChainTooLong
                | ArcEvent::InvalidInstance
                | ArcEvent::InvalidCv
                | ArcEvent::HasHeaderTag
                | ArcEvent::BrokenChain,
            ) => true,
            EventType::Dkim(_) => true,
            EventType::Dmarc(_) => true,
            EventType::Iprev(_) => true,
            EventType::Dane(
                DaneEvent::AuthenticationSuccess
                | DaneEvent::AuthenticationFailure
                | DaneEvent::NoCertificatesFound
                | DaneEvent::CertificateParseError
                | DaneEvent::TlsaRecordFetchError
                | DaneEvent::TlsaRecordNotFound
                | DaneEvent::TlsaRecordNotDnssecSigned
                | DaneEvent::TlsaRecordInvalid,
            ) => true,
            EventType::Spf(_) => true,
            EventType::MailAuth(_) => true,
            EventType::Tls(TlsEvent::HandshakeError) => true,
            EventType::Sieve(
                SieveEvent::ActionAccept
                | SieveEvent::ActionAcceptReplace
                | SieveEvent::ActionDiscard
                | SieveEvent::ActionReject
                | SieveEvent::SendMessage
                | SieveEvent::MessageTooLarge
                | SieveEvent::RuntimeError
                | SieveEvent::UnexpectedError
                | SieveEvent::NotSupported
                | SieveEvent::QuotaExceeded,
            ) => true,
            EventType::Spam(
                SpamEvent::PyzorError
                | SpamEvent::ListUpdated
                | SpamEvent::Train
                | SpamEvent::TrainError
                | SpamEvent::Classify
                | SpamEvent::ClassifyError
                | SpamEvent::NotEnoughTrainingData,
            ) => true,
            EventType::PushSubscription(_) => true,
            EventType::Cluster(
                ClusterEvent::PeerOffline
                | ClusterEvent::PeerSuspected
                | ClusterEvent::PeerSuspectedIsAlive
                | ClusterEvent::EmptyPacket
                | ClusterEvent::InvalidPacket
                | ClusterEvent::DecryptionError
                | ClusterEvent::Error,
            ) => true,
            EventType::Housekeeper(_) => false,
            EventType::FtsIndex(
                FtsIndexEvent::Index
                | FtsIndexEvent::BlobNotFound
                | FtsIndexEvent::MetadataNotFound,
            ) => true,
            EventType::Milter(
                MilterEvent::ActionAccept
                | MilterEvent::ActionDiscard
                | MilterEvent::ActionReject
                | MilterEvent::ActionTempFail
                | MilterEvent::ActionReplyCode
                | MilterEvent::ActionConnectionFailure
                | MilterEvent::ActionShutdown,
            ) => true,
            EventType::MtaHook(_) => true,
            EventType::Delivery(
                DeliveryEvent::AttemptStart
                | DeliveryEvent::AttemptEnd
                | DeliveryEvent::MxLookupFailed
                | DeliveryEvent::IpLookupFailed
                | DeliveryEvent::NullMx
                | DeliveryEvent::GreetingFailed
                | DeliveryEvent::EhloRejected
                | DeliveryEvent::AuthFailed
                | DeliveryEvent::MailFromRejected
                | DeliveryEvent::Delivered
                | DeliveryEvent::RcptToRejected
                | DeliveryEvent::RcptToFailed
                | DeliveryEvent::MessageRejected
                | DeliveryEvent::StartTlsUnavailable
                | DeliveryEvent::StartTlsError
                | DeliveryEvent::StartTlsDisabled
                | DeliveryEvent::ImplicitTlsError
                | DeliveryEvent::ConcurrencyLimitExceeded
                | DeliveryEvent::RateLimitExceeded
                | DeliveryEvent::DoubleBounce
                | DeliveryEvent::DsnSuccess
                | DeliveryEvent::DsnTempFail
                | DeliveryEvent::DsnPermFail,
            ) => true,
            EventType::Queue(
                QueueEvent::QueueMessage
                | QueueEvent::QueueMessageAuthenticated
                | QueueEvent::QueueReport
                | QueueEvent::QueueDsn
                | QueueEvent::QueueAutogenerated
                | QueueEvent::Rescheduled
                | QueueEvent::BlobNotFound
                | QueueEvent::RateLimitExceeded
                | QueueEvent::ConcurrencyLimitExceeded
                | QueueEvent::QuotaExceeded,
            ) => true,
            EventType::TlsRpt(_) => false,
            EventType::MtaSts(
                MtaStsEvent::Authorized | MtaStsEvent::NotAuthorized | MtaStsEvent::InvalidPolicy,
            ) => true,
            EventType::IncomingReport(_) => true,
            EventType::OutgoingReport(
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
                | OutgoingReportEvent::NotFound
                | OutgoingReportEvent::SubmissionError
                | OutgoingReportEvent::NoRecipientsFound,
            ) => true,
            EventType::Telemetry(
                TelemetryEvent::LogError
                | TelemetryEvent::WebhookError
                | TelemetryEvent::OtelExporterError
                | TelemetryEvent::OtelMetricsExporterError
                | TelemetryEvent::PrometheusExporterError
                | TelemetryEvent::JournalError,
            ) => true,
            _ => false,
        }
    }
}
