/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod metrics;
pub mod tracers;
pub mod webhooks;

use std::time::Duration;

use tracers::log::spawn_log_tracer;
use tracers::otel::spawn_otel_tracer;
use tracers::stdout::spawn_console_tracer;
use trc::{ipc::subscriber::SubscriberBuilder, Collector};
use webhooks::spawn_webhook_tracer;

use crate::config::telemetry::{Telemetry, TelemetrySubscriberType};

pub const LONG_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

impl Telemetry {
    pub fn enable(self, is_enterprise: bool) {
        // Spawn tracers
        for tracer in self.tracers.subscribers {
            tracer.typ.spawn(
                SubscriberBuilder::new(tracer.id)
                    .with_interests(tracer.interests)
                    .with_lossy(tracer.lossy),
                is_enterprise,
            );
        }

        // Update global collector
        Collector::set_interests(self.tracers.interests);
        Collector::update_custom_levels(self.tracers.levels);
        Collector::set_metrics(self.metrics);
        Collector::reload();
    }

    pub fn update(self, is_enterprise: bool) {
        // Remove tracers that are no longer active
        let active_subscribers = Collector::get_subscribers();
        for subscribed_id in &active_subscribers {
            if !self
                .tracers
                .subscribers
                .iter()
                .any(|tracer| tracer.id == *subscribed_id)
            {
                Collector::remove_subscriber(subscribed_id.clone());
            }
        }

        // Activate new tracers or update existing ones
        for tracer in self.tracers.subscribers {
            if active_subscribers.contains(&tracer.id) {
                Collector::update_subscriber(tracer.id, tracer.interests, tracer.lossy);
            } else {
                tracer.typ.spawn(
                    SubscriberBuilder::new(tracer.id)
                        .with_interests(tracer.interests)
                        .with_lossy(tracer.lossy),
                    is_enterprise,
                );
            }
        }

        // Update global collector
        Collector::set_interests(self.tracers.interests);
        Collector::update_custom_levels(self.tracers.levels);
        Collector::set_metrics(self.metrics);
        Collector::reload();
    }

    #[cfg(feature = "test_mode")]
    pub fn test_tracer(level: trc::Level) {
        let mut interests = trc::ipc::subscriber::Interests::default();
        for event in trc::EventType::variants() {
            if level.is_contained(event.level()) {
                interests.set(event);
            }
        }

        spawn_console_tracer(
            SubscriberBuilder::new("stderr".to_string())
                .with_interests(interests.clone())
                .with_lossy(false),
            crate::config::telemetry::ConsoleTracer {
                ansi: true,
                multiline: false,
                buffered: false,
            },
        );

        Collector::union_interests(interests);
        Collector::reload();
    }
}

impl TelemetrySubscriberType {
    pub fn spawn(self, builder: SubscriberBuilder, is_enterprise: bool) {
        match self {
            TelemetrySubscriberType::ConsoleTracer(settings) => {
                spawn_console_tracer(builder, settings)
            }
            TelemetrySubscriberType::LogTracer(settings) => spawn_log_tracer(builder, settings),
            TelemetrySubscriberType::Webhook(settings) => spawn_webhook_tracer(builder, settings),
            TelemetrySubscriberType::OtelTracer(settings) => spawn_otel_tracer(builder, settings),
            #[cfg(unix)]
            TelemetrySubscriberType::JournalTracer(subscriber) => {
                tracers::journald::spawn_journald_tracer(builder, subscriber)
            }
            #[cfg(feature = "enterprise")]
            TelemetrySubscriberType::StoreTracer(subscriber) => {
                if is_enterprise {
                    tracers::store::spawn_store_tracer(builder, subscriber)
                }
            }
        }
    }
}
