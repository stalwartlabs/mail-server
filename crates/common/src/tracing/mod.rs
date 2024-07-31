/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod log;
pub mod otel;
pub mod stdout;
pub mod webhook;

use std::time::Duration;

use log::spawn_log_tracer;
use otel::spawn_otel_tracer;
use stdout::spawn_console_tracer;
use trc::{collector::Collector, subscriber::SubscriberBuilder};
use webhook::spawn_webhook_tracer;

use crate::config::tracers::{TracerType, Tracers};

pub const LONG_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

impl Tracers {
    pub fn enable(self) {
        // Spawn tracers
        for tracer in self.tracers {
            tracer.typ.spawn(
                SubscriberBuilder::new(tracer.id)
                    .with_interests(tracer.interests)
                    .with_lossy(tracer.lossy),
            );
        }

        // Update global collector
        Collector::set_interests(self.global_interests);
        Collector::update_custom_levels(self.custom_levels);
        Collector::reload();
    }

    pub fn update(self) {
        // Remove tracers that are no longer active
        let active_subscribers = Collector::get_subscribers();
        for subscribed_id in &active_subscribers {
            if !self
                .tracers
                .iter()
                .any(|tracer| tracer.id == *subscribed_id)
            {
                Collector::remove_subscriber(subscribed_id.clone());
            }
        }

        // Activate new tracers or update existing ones
        for tracer in self.tracers {
            if active_subscribers.contains(&tracer.id) {
                Collector::update_subscriber(tracer.id, tracer.interests, tracer.lossy);
            } else {
                tracer.typ.spawn(
                    SubscriberBuilder::new(tracer.id)
                        .with_interests(tracer.interests)
                        .with_lossy(tracer.lossy),
                );
            }
        }

        // Update global collector
        Collector::set_interests(self.global_interests);
        Collector::update_custom_levels(self.custom_levels);
        Collector::reload();
    }

    #[cfg(feature = "test_mode")]
    pub fn test_tracer(level: trc::Level) {
        let mut interests = trc::subscriber::Interests::default();
        for event in trc::EventType::variants() {
            if level.is_contained(event.level()) {
                interests.set(event);
            }
        }

        spawn_console_tracer(
            SubscriberBuilder::new("stderr".to_string())
                .with_interests(interests.clone())
                .with_lossy(false),
            crate::config::tracers::ConsoleTracer {
                ansi: true,
                multiline: false,
                buffered: true,
            },
        );

        Collector::union_interests(interests);
        Collector::reload();
    }
}

impl TracerType {
    pub fn spawn(self, builder: SubscriberBuilder) {
        let todo = "journal";
        match self {
            TracerType::Console(settings) => spawn_console_tracer(builder, settings),
            TracerType::Log(settings) => spawn_log_tracer(builder, settings),
            TracerType::Webhook(settings) => spawn_webhook_tracer(builder, settings),
            TracerType::Otel(settings) => spawn_otel_tracer(builder, settings),
            TracerType::Journal => todo!(),
        }
    }
}
