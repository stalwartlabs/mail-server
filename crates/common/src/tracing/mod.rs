/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod log;
pub mod stdout;

use log::spawn_log_tracer;
use stdout::spawn_console_tracer;
use trc::{collector::Collector, subscriber::SubscriberBuilder};

use crate::config::tracers::{ConsoleTracer, TracerType, Tracers};

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
            if event.level() <= level {
                interests.set(event);
            }
        }

        spawn_console_tracer(
            SubscriberBuilder::new("stdout".to_string())
                .with_interests(interests.clone())
                .with_lossy(false),
            ConsoleTracer {
                ansi: true,
                multiline: false,
                buffered: true,
            },
        );

        Collector::set_interests(interests);
        Collector::reload();
    }
}

impl TracerType {
    pub fn spawn(self, builder: SubscriberBuilder) {
        match self {
            TracerType::Console(settings) => spawn_console_tracer(builder, settings),
            TracerType::Log(settings) => spawn_log_tracer(builder, settings),
            TracerType::Otel(_) => todo!(),
            TracerType::Webhook(_) => todo!(),
            TracerType::Journal => todo!(),
        }
    }
}

/*
impl Tracers {
    pub fn enable(self, config: &mut Config) -> Option<Vec<WorkerGuard>> {
        let mut layers: Option<Box<dyn Layer<Registry> + Sync + Send>> = None;
        let mut guards = Vec::new();

        for tracer in self.tracers {
            let (Tracer::Stdout { level, .. }
            | Tracer::Log { level, .. }
            | Tracer::Journal { level, .. }
            | Tracer::Otel { level, .. }) = tracer;

            let filter = match EnvFilter::builder().parse(format!(
                "smtp={level},imap={level},jmap={level},pop3={level},store={level},common={level},utils={level},directory={level},se_common={level}"
            )) {
                Ok(filter) => {
                    filter
                }
                Err(err) => {
                    config.new_build_error("tracer", format!("Failed to set env filter: {err}"));
                    continue;
                }
            };

            let layer = match tracer {
                Tracer::Stdout { ansi, .. } => tracing_subscriber::fmt::layer()
                    .with_ansi(ansi)
                    .with_filter(filter)
                    .boxed(),
                Tracer::Log { appender, ansi, .. } => {
                    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
                    guards.push(guard);
                    tracing_subscriber::fmt::layer()
                        .with_writer(non_blocking)
                        .with_ansi(ansi)
                        .with_filter(filter)
                        .boxed()
                }
                Tracer::Otel { tracer, .. } => {
                    let tracer = match tracer {
                        OtelTracer::Gprc(exporter) => opentelemetry_otlp::new_pipeline()
                            .tracing()
                            .with_exporter(exporter),
                        OtelTracer::Http(exporter) => opentelemetry_otlp::new_pipeline()
                            .tracing()
                            .with_exporter(exporter),
                    }
                    .with_trace_config(
                        trace::config()
                            .with_resource(Resource::new(vec![
                                KeyValue::new(SERVICE_NAME, "stalwart-mail".to_string()),
                                KeyValue::new(
                                    SERVICE_VERSION,
                                    env!("CARGO_PKG_VERSION").to_string(),
                                ),
                            ]))
                            .with_sampler(Sampler::AlwaysOn),
                    )
                    .install_batch(opentelemetry_sdk::runtime::Tokio);

                    match tracer {
                        Ok(tracer) => tracing_opentelemetry::layer()
                            .with_tracer(tracer)
                            .with_filter(filter)
                            .boxed(),
                        Err(err) => {
                            config.new_build_error(
                                "tracer",
                                format!("Failed to start OpenTelemetry: {err}"),
                            );
                            continue;
                        }
                    }
                }
                Tracer::Journal { .. } => {
                    #[cfg(unix)]
                    {
                        match tracing_journald::layer() {
                            Ok(layer) => layer.with_filter(filter).boxed(),
                            Err(err) => {
                                config.new_build_error(
                                    "tracer",
                                    format!("Failed to start Journald: {err}"),
                                );
                                continue;
                            }
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        config.new_build_error(
                            "tracer",
                            "Journald is only available on Unix systems.",
                        );
                        continue;
                    }
                }
            };

            layers = Some(match layers {
                Some(layers) => layers.and_then(layer).boxed(),
                None => layer,
            });
        }

        match tracing_subscriber::registry().with(layers?).try_init() {
            Ok(_) => Some(guards),
            Err(err) => {
                config.new_build_error("tracer", format!("Failed to start tracing: {err}"));
                None
            }
        }
    }
}
*/
