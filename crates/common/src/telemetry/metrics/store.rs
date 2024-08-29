/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::{future::Future, sync::Arc, time::Duration};

use ahash::AHashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use store::{
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        now, BatchBuilder, TelemetryClass, ValueClass,
    },
    IterateParams, Store, ValueKey, U32_LEN, U64_LEN,
};
use trc::*;
use utils::codec::leb128::Leb128Reader;

use crate::Core;

pub trait MetricsStore: Sync + Send {
    fn write_metrics(
        &self,
        core: Arc<Core>,
        timestamp: u64,
        history: SharedMetricHistory,
    ) -> impl Future<Output = trc::Result<()>> + Send;
    fn query_metrics(
        &self,
        from_timestamp: u64,
        to_timestamp: u64,
    ) -> impl Future<Output = trc::Result<Vec<Metric<EventType, MetricType, u64>>>> + Send;
    fn purge_metrics(&self, period: Duration) -> impl Future<Output = trc::Result<()>> + Send;
}

#[derive(Default)]
pub struct MetricsHistory {
    events: AHashMap<EventType, u32>,
    histograms: AHashMap<MetricType, HistogramHistory>,
}

#[derive(Default)]
struct HistogramHistory {
    sum: u64,
    count: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum Metric<CI, MI, T> {
    Counter {
        id: CI,
        timestamp: T,
        value: u64,
    },
    Gauge {
        id: MI,
        timestamp: T,
        value: u64,
    },
    Histogram {
        id: MI,
        timestamp: T,
        count: u64,
        sum: u64,
    },
}

pub type SharedMetricHistory = Arc<Mutex<MetricsHistory>>;

const TYPE_COUNTER: u64 = 0x00;
const TYPE_HISTOGRAM: u64 = 0x01;
const TYPE_GAUGE: u64 = 0x02;

impl MetricsStore for Store {
    async fn write_metrics(
        &self,
        core: Arc<Core>,
        timestamp: u64,
        history_: SharedMetricHistory,
    ) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        {
            let node_id = core.network.node_id;
            let mut history = history_.lock();
            for event in [
                EventType::Smtp(SmtpEvent::ConnectionStart),
                EventType::Imap(ImapEvent::ConnectionStart),
                EventType::Pop3(Pop3Event::ConnectionStart),
                EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
                EventType::Http(HttpEvent::ConnectionStart),
                EventType::Delivery(DeliveryEvent::AttemptStart),
                EventType::Queue(QueueEvent::QueueMessage),
                EventType::Queue(QueueEvent::QueueMessageAuthenticated),
                EventType::Queue(QueueEvent::QueueDsn),
                EventType::Queue(QueueEvent::QueueReport),
                EventType::MessageIngest(MessageIngestEvent::Ham),
                EventType::MessageIngest(MessageIngestEvent::Spam),
                EventType::Auth(AuthEvent::Failed),
                EventType::Security(SecurityEvent::AuthenticationBan),
                EventType::Security(SecurityEvent::BruteForceBan),
                EventType::Security(SecurityEvent::LoiterBan),
                EventType::Security(SecurityEvent::IpBlocked),
                EventType::IncomingReport(IncomingReportEvent::DmarcReport),
                EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
                EventType::IncomingReport(IncomingReportEvent::TlsReport),
                EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
            ] {
                let reading = Collector::read_event_metric(event.id());
                if reading > 0 {
                    let history = history.events.entry(event).or_insert(0);
                    let diff = reading - *history;
                    if diff > 0 {
                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric {
                                timestamp,
                                metric_id: (event.code() << 2) | TYPE_COUNTER,
                                node_id,
                            }),
                            KeySerializer::new(U32_LEN).write_leb128(diff).finalize(),
                        );
                    }
                    *history = reading;
                }
            }

            for gauge in Collector::collect_gauges(true) {
                let gauge_id = gauge.id();
                if matches!(gauge_id, MetricType::QueueCount | MetricType::ServerMemory) {
                    let value = gauge.get();
                    if value > 0 {
                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric {
                                timestamp,
                                metric_id: (gauge_id.code() << 2) | TYPE_GAUGE,
                                node_id,
                            }),
                            KeySerializer::new(U32_LEN).write_leb128(value).finalize(),
                        );
                    }
                }
            }

            for histogram in Collector::collect_histograms(true) {
                let histogram_id = histogram.id();
                if matches!(
                    histogram_id,
                    MetricType::MessageIngestionTime
                        | MetricType::MessageFtsIndexTime
                        | MetricType::DeliveryTotalTime
                        | MetricType::DeliveryTime
                        | MetricType::DnsLookupTime
                ) {
                    let history = history.histograms.entry(histogram_id).or_default();
                    let sum = histogram.sum();
                    let count = histogram.count();
                    let diff_sum = sum - history.sum;
                    let diff_count = count - history.count;
                    if diff_sum > 0 || diff_count > 0 {
                        batch.set(
                            ValueClass::Telemetry(TelemetryClass::Metric {
                                timestamp,
                                metric_id: (histogram_id.code() << 2) | TYPE_HISTOGRAM,
                                node_id,
                            }),
                            KeySerializer::new(U32_LEN)
                                .write_leb128(diff_count)
                                .write_leb128(diff_sum)
                                .finalize(),
                        );
                    }
                    history.sum = sum;
                    history.count = count;
                }
            }
        }

        if !batch.is_empty() {
            self.write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    async fn query_metrics(
        &self,
        from_timestamp: u64,
        to_timestamp: u64,
    ) -> trc::Result<Vec<Metric<EventType, MetricType, u64>>> {
        let mut metrics = Vec::new();
        self.iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric {
                    timestamp: from_timestamp,
                    metric_id: 0,
                    node_id: 0,
                })),
                ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric {
                    timestamp: to_timestamp,
                    metric_id: 0,
                    node_id: 0,
                })),
            ),
            |key, value| {
                let timestamp = key.deserialize_be_u64(0).caused_by(trc::location!())?;
                let (metric_type, _) = key
                    .get(U64_LEN..)
                    .and_then(|bytes| bytes.read_leb128::<u64>())
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                match metric_type & 0x03 {
                    TYPE_COUNTER => {
                        let id = EventType::from_code(metric_type >> 2).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;
                        let (value, _) = value.read_leb128::<u64>().ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?;
                        metrics.push(Metric::Counter {
                            id,
                            timestamp,
                            value,
                        });
                    }
                    TYPE_HISTOGRAM => {
                        let id = MetricType::from_code(metric_type >> 2).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;
                        let (count, bytes_read) = value.read_leb128::<u64>().ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?;
                        let (sum, _) = value
                            .get(bytes_read..)
                            .and_then(|bytes| bytes.read_leb128::<u64>())
                            .ok_or_else(|| {
                                trc::Error::corrupted_key(key, value.into(), trc::location!())
                            })?;
                        metrics.push(Metric::Histogram {
                            id,
                            timestamp,
                            count,
                            sum,
                        });
                    }
                    TYPE_GAUGE => {
                        let id = MetricType::from_code(metric_type >> 2).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;
                        let (value, _) = value.read_leb128::<u64>().ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?;
                        metrics.push(Metric::Gauge {
                            id,
                            timestamp,
                            value,
                        });
                    }
                    _ => return Err(trc::Error::corrupted_key(key, None, trc::location!())),
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(metrics)
    }

    async fn purge_metrics(&self, period: Duration) -> trc::Result<()> {
        self.delete_range(
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric {
                timestamp: 0,
                metric_id: 0,
                node_id: 0,
            })),
            ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric {
                timestamp: now() - period.as_secs(),
                metric_id: 0,
                node_id: 0,
            })),
        )
        .await
        .caused_by(trc::location!())
    }
}

impl MetricsHistory {
    pub fn init() -> SharedMetricHistory {
        Arc::new(Mutex::new(Self::default()))
    }
}
