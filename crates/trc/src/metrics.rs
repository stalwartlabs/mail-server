/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use crate::{
    atomic::{AtomicCounter, AtomicGauge, AtomicHistogram, AtomicU32Array},
    collector::{Collector, GlobalInterests, EVENT_TYPES},
    subscriber::Interests,
    DeliveryEvent, EventType, FtsIndexEvent, HttpEvent, ImapEvent, Key, ManageSieveEvent,
    MessageIngestEvent, NetworkEvent, Pop3Event, Protocol, QueueEvent, SmtpEvent, StoreEvent,
    Value, TOTAL_EVENT_COUNT,
};

pub(crate) static METRIC_INTERESTS: GlobalInterests = GlobalInterests::new();

static EVENT_COUNTERS: AtomicU32Array<TOTAL_EVENT_COUNT> = AtomicU32Array::new();
static CONNECTION_METRICS: [ConnectionMetrics; TOTAL_CONN_TYPES] = init_conn_metrics();

static MESSAGE_INGESTION_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("message.ingestion-time", "Message ingestion time");
static MESSAGE_INDEX_TIME: AtomicHistogram<12> = AtomicHistogram::<10>::new_short_durations(
    "message.fts-index-time",
    "Message full-text indexing time",
);
static MESSAGE_DELIVERY_TIME: AtomicHistogram<12> = AtomicHistogram::<18>::new_long_durations(
    "message.outgoing-delivery-time",
    "Total message delivery time from submission to delivery",
);

static MESSAGE_INCOMING_SIZE: AtomicHistogram<12> =
    AtomicHistogram::<12>::new_message_sizes("message.incoming-size", "Received message size");
static MESSAGE_SUBMISSION_SIZE: AtomicHistogram<12> = AtomicHistogram::<12>::new_message_sizes(
    "message.incoming-submission-size",
    "Received message size from authenticated users",
);
static MESSAGE_OUT_REPORT_SIZE: AtomicHistogram<12> = AtomicHistogram::<12>::new_message_sizes(
    "message.outgoing-report-size",
    "Outgoing report size",
);

static STORE_DATA_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("store.data-read-time", "Data store read time");
static STORE_DATA_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("store.data-write-time", "Data store write time");
static STORE_BLOB_READ_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("store.blob-read-time", "Blob store read time");
static STORE_BLOB_WRITE_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("store.blob-write-time", "Blob store write time");

static DNS_LOOKUP_TIME: AtomicHistogram<12> =
    AtomicHistogram::<10>::new_short_durations("dns.lookup-time", "DNS lookup time");

const CONN_SMTP_IN: usize = 0;
const CONN_SMTP_OUT: usize = 1;
const CONN_IMAP: usize = 2;
const CONN_POP3: usize = 3;
const CONN_HTTP: usize = 4;
const CONN_SIEVE: usize = 5;
const TOTAL_CONN_TYPES: usize = 6;

pub struct ConnectionMetrics {
    pub total_connections: AtomicCounter,
    pub active_connections: AtomicGauge,
    pub bytes_sent: AtomicCounter,
    pub bytes_received: AtomicCounter,
    pub elapsed: AtomicHistogram<12>,
}

pub struct EventCounter {
    id: &'static str,
    description: &'static str,
    value: u32,
}

impl Collector {
    pub fn record_metric(event: EventType, event_id: usize, keys: &[(Key, Value)]) {
        // Increment the event counter
        EVENT_COUNTERS.add(event_id, 1);

        // Extract variables
        let mut elapsed = 0;
        let mut size = 0;
        let mut protocol = Protocol::Gossip;
        for (key, value) in keys {
            match (key, value) {
                (Key::Elapsed, Value::Duration(d)) => elapsed = *d,
                (Key::Size, Value::UInt(s)) => size = *s,
                (Key::Protocol, Value::Protocol(p)) => protocol = *p,
                _ => {}
            }
        }

        match event {
            EventType::Network(NetworkEvent::ConnectionStart) => {
                let conn = &CONNECTION_METRICS[protocol.idx()];
                conn.total_connections.increment();
                conn.active_connections.increment();
            }
            EventType::Network(NetworkEvent::ConnectionEnd) => {
                let conn = &CONNECTION_METRICS[protocol.idx()];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::AttemptStart) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.total_connections.increment();
                conn.active_connections.increment();
            }
            EventType::Delivery(DeliveryEvent::AttemptEnd) => {
                let conn = &CONNECTION_METRICS[CONN_SMTP_OUT];
                conn.active_connections.decrement();
                conn.elapsed.observe(elapsed);
            }
            EventType::Delivery(DeliveryEvent::Completed) => {
                MESSAGE_DELIVERY_TIME.observe(elapsed);
            }
            EventType::Smtp(SmtpEvent::RawInput) => {
                CONNECTION_METRICS[CONN_SMTP_IN]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::Smtp(SmtpEvent::RawOutput) => {
                CONNECTION_METRICS[CONN_SMTP_IN]
                    .bytes_sent
                    .increment_by(size);
            }
            EventType::Imap(ImapEvent::RawInput) => {
                CONNECTION_METRICS[CONN_IMAP]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::Imap(ImapEvent::RawOutput) => {
                CONNECTION_METRICS[CONN_IMAP].bytes_sent.increment_by(size);
            }
            EventType::Http(HttpEvent::RequestBody) => {
                CONNECTION_METRICS[CONN_HTTP]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::Http(HttpEvent::ResponseBody) => {
                CONNECTION_METRICS[CONN_HTTP].bytes_sent.increment_by(size);
            }
            EventType::Pop3(Pop3Event::RawInput) => {
                CONNECTION_METRICS[CONN_POP3]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::Pop3(Pop3Event::RawOutput) => {
                CONNECTION_METRICS[CONN_POP3].bytes_sent.increment_by(size);
            }
            EventType::ManageSieve(ManageSieveEvent::RawInput) => {
                CONNECTION_METRICS[CONN_SIEVE]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::ManageSieve(ManageSieveEvent::RawOutput) => {
                CONNECTION_METRICS[CONN_SIEVE].bytes_sent.increment_by(size);
            }
            EventType::Delivery(DeliveryEvent::RawInput) => {
                CONNECTION_METRICS[CONN_SMTP_OUT]
                    .bytes_received
                    .increment_by(size);
            }
            EventType::Delivery(DeliveryEvent::RawOutput) => {
                CONNECTION_METRICS[CONN_SMTP_OUT]
                    .bytes_sent
                    .increment_by(size);
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
            }
            EventType::Queue(QueueEvent::QueueMessageSubmission) => {
                MESSAGE_SUBMISSION_SIZE.observe(size);
            }
            EventType::Queue(QueueEvent::QueueReport) => {
                MESSAGE_OUT_REPORT_SIZE.observe(size);
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

    pub fn collect_event_counters(_is_enterprise: bool) -> impl Iterator<Item = EventCounter> {
        EVENT_COUNTERS
            .inner()
            .iter()
            .enumerate()
            .filter_map(|(event_id, value)| {
                let value = value.load(Ordering::Relaxed);
                if value > 0 {
                    let event = EVENT_TYPES[event_id];

                    Some(EventCounter {
                        id: event.name(),
                        description: event.description(),
                        value,
                    })
                } else {
                    None
                }
            })
    }

    pub fn collect_counters(_is_enterprise: bool) -> impl Iterator<Item = &'static AtomicCounter> {
        CONNECTION_METRICS
            .iter()
            .flat_map(|m| [&m.total_connections, &m.bytes_sent, &m.bytes_received])
            .filter(|c| c.is_active())
    }

    pub fn collect_gauges(_is_enterprise: bool) -> impl Iterator<Item = &'static AtomicGauge> {
        CONNECTION_METRICS.iter().map(|m| &m.active_connections)
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
}

impl EventCounter {
    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn description(&self) -> &'static str {
        self.description
    }

    pub fn value(&self) -> u64 {
        self.value as u64
    }
}

impl ConnectionMetrics {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            total_connections: AtomicCounter::new("", "", ""),
            active_connections: AtomicGauge::new("", "", ""),
            bytes_sent: AtomicCounter::new("", "", ""),
            bytes_received: AtomicCounter::new("", "", ""),
            elapsed: AtomicHistogram::<18>::new_medium_durations("", ""),
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const fn init_conn_metrics() -> [ConnectionMetrics; TOTAL_CONN_TYPES] {
    const INIT: ConnectionMetrics = ConnectionMetrics::new();
    let mut array = [INIT; TOTAL_CONN_TYPES];
    let mut i = 0;
    while i < TOTAL_CONN_TYPES {
        let text = match i {
            CONN_HTTP => &[
                ("http.total-connections", "Total HTTP connections", "number"),
                (
                    "http.active-connections",
                    "Active HTTP connections",
                    "number",
                ),
                ("http.bytes-sent", "Bytes sent over HTTP", "bytes"),
                ("http.bytes-received", "Bytes received over HTTP", "bytes"),
                ("http.request-time", "HTTP request duration", "milliseconds"),
            ],
            CONN_IMAP => &[
                ("imap.total-connections", "Total IMAP connections", "number"),
                (
                    "imap.active-connections",
                    "Active IMAP connections",
                    "number",
                ),
                ("imap.bytes-sent", "Bytes sent over IMAP", "bytes"),
                ("imap.bytes-received", "Bytes received over IMAP", "bytes"),
                ("imap.request-time", "IMAP request duration", "milliseconds"),
            ],
            CONN_POP3 => &[
                ("pop3.total-connections", "Total POP3 connections", "number"),
                (
                    "pop3.active-connections",
                    "Active POP3 connections",
                    "number",
                ),
                ("pop3.bytes-sent", "Bytes sent over POP3", "bytes"),
                ("pop3.bytes-received", "Bytes received over POP3", "bytes"),
                ("pop3.request-time", "POP3 request duration", "milliseconds"),
            ],
            CONN_SMTP_IN => &[
                (
                    "smtp-in.total-connections",
                    "Total SMTP incoming connections",
                    "number",
                ),
                (
                    "smtp-in.active-connections",
                    "Active SMTP incoming connections",
                    "number",
                ),
                (
                    "smtp-in.bytes-sent",
                    "Bytes sent over SMTP incoming",
                    "bytes",
                ),
                (
                    "smtp-in.bytes-received",
                    "Bytes received over SMTP incoming",
                    "bytes",
                ),
                (
                    "smtp-in.request-time",
                    "SMTP incoming request duration",
                    "milliseconds",
                ),
            ],
            CONN_SMTP_OUT => &[
                (
                    "smtp-out.total-connections",
                    "Total SMTP outgoing connections",
                    "number",
                ),
                (
                    "smtp-out.active-connections",
                    "Active SMTP outgoing connections",
                    "number",
                ),
                (
                    "smtp-out.bytes-sent",
                    "Bytes sent over SMTP outgoing",
                    "bytes",
                ),
                (
                    "smtp-out.bytes-received",
                    "Bytes received over SMTP outgoing",
                    "bytes",
                ),
                (
                    "smtp-out.request-time",
                    "SMTP outgoing request duration",
                    "milliseconds",
                ),
            ],
            CONN_SIEVE => &[
                (
                    "sieve.total-connections",
                    "Total ManageSieve connections",
                    "number",
                ),
                (
                    "sieve.active-connections",
                    "Active ManageSieve connections",
                    "number",
                ),
                ("sieve.bytes-sent", "Bytes sent over ManageSieve", "bytes"),
                (
                    "sieve.bytes-received",
                    "Bytes received over ManageSieve",
                    "bytes",
                ),
                (
                    "sieve.request-time",
                    "ManageSieve request duration",
                    "milliseconds",
                ),
            ],
            _ => &[
                ("", "", ""),
                ("", "", ""),
                ("", "", ""),
                ("", "", ""),
                ("", "", ""),
            ],
        };
        array[i] = ConnectionMetrics {
            total_connections: AtomicCounter::new(text[0].0, text[0].1, text[0].2),
            active_connections: AtomicGauge::new(text[1].0, text[1].1, text[1].2),
            bytes_sent: AtomicCounter::new(text[2].0, text[2].1, text[2].2),
            bytes_received: AtomicCounter::new(text[3].0, text[3].1, text[3].2),
            elapsed: AtomicHistogram::<18>::new_medium_durations(text[4].0, text[4].1),
        };
        i += 1;
    }
    array
}

impl Protocol {
    fn idx(&self) -> usize {
        match self {
            Protocol::Jmap => CONN_IMAP,
            Protocol::Imap => CONN_IMAP,
            Protocol::Lmtp | Protocol::Smtp => CONN_SMTP_IN,
            Protocol::ManageSieve => CONN_SIEVE,
            Protocol::Pop3 => CONN_POP3,
            Protocol::Http => CONN_HTTP,
            _ => unreachable!(),
        }
    }
}
