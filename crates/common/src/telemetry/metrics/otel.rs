/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::SystemTime};

use opentelemetry::global::set_error_handler;
use opentelemetry_sdk::metrics::data::{
    DataPoint, Gauge, Histogram, HistogramDataPoint, Metric, ResourceMetrics, ScopeMetrics, Sum,
    Temporality,
};
use trc::{Collector, TelemetryEvent};

use crate::{config::telemetry::OtelMetrics, Core};

impl OtelMetrics {
    pub async fn push_metrics(&self, core: Arc<Core>, start_time: SystemTime) {
        let mut metrics = Vec::with_capacity(256);
        let now = SystemTime::now();

        #[cfg(feature = "enterprise")]
        let is_enterprise = core.is_enterprise_edition();

        #[cfg(not(feature = "enterprise"))]
        let is_enterprise = false;

        // Add counters
        for counter in Collector::collect_counters(is_enterprise) {
            metrics.push(Metric {
                name: counter.id().name().into(),
                description: counter.id().description().into(),
                unit: "events".into(),
                data: Box::new(Sum {
                    data_points: vec![DataPoint {
                        attributes: vec![],
                        start_time: start_time.into(),
                        time: now.into(),
                        value: counter.value(),
                        exemplars: vec![],
                    }],
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            });
        }

        // Add gauges
        for gauge in Collector::collect_gauges(is_enterprise) {
            metrics.push(Metric {
                name: gauge.id().name().into(),
                description: gauge.id().description().into(),
                unit: gauge.id().unit().into(),
                data: Box::new(Gauge {
                    data_points: vec![DataPoint {
                        attributes: vec![],
                        start_time: start_time.into(),
                        time: now.into(),
                        value: gauge.get(),
                        exemplars: vec![],
                    }],
                }),
            });
        }

        // Add histograms
        for histogram in Collector::collect_histograms(is_enterprise) {
            metrics.push(Metric {
                name: histogram.id().name().into(),
                description: histogram.id().description().into(),
                unit: histogram.id().unit().into(),
                data: Box::new(Histogram {
                    data_points: vec![HistogramDataPoint {
                        attributes: vec![],
                        start_time,
                        time: now,
                        count: histogram.count(),
                        bounds: histogram.upper_bounds_vec(),
                        bucket_counts: histogram.buckets_vec(),
                        min: histogram.min(),
                        max: histogram.max(),
                        sum: histogram.sum(),
                        exemplars: vec![],
                    }],
                    temporality: Temporality::Cumulative,
                }),
            });
        }

        // Export metrics
        if let Err(err) = self
            .exporter
            .export(&mut ResourceMetrics {
                resource: self.resource.clone(),
                scope_metrics: vec![ScopeMetrics {
                    scope: self.instrumentation.clone(),
                    metrics,
                }],
            })
            .await
        {
            trc::event!(
                Telemetry(TelemetryEvent::OtelMetricsExporterError),
                Reason = err.to_string(),
            );
        }
    }

    pub fn enable_errors() {
        let _ = set_error_handler(|error| {
            trc::event!(
                Telemetry(TelemetryEvent::OtelMetricsExporterError),
                Reason = error.to_string(),
            );
        });
    }
}
