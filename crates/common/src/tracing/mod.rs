/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod stdout;
//pub mod webhook;

use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    trace::{self, Sampler},
    Resource,
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use stdout::spawn_stdout_tracer;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};
use trc::subscriber::SubscriberBuilder;
use utils::config::Config;

use crate::config::tracers::{OtelTracer, Tracer, Tracers};

impl Tracer {
    pub fn spawn(self) {
        match self {
            Tracer::Stdout { id, level, ansi } => {
                spawn_stdout_tracer(SubscriberBuilder::new(id).with_level(level), ansi);
            }
            Tracer::Log {
                id,
                level,
                appender,
                ansi,
            } => todo!(),
            Tracer::Journal { id, level } => todo!(),
            Tracer::Otel { id, level, tracer } => todo!(),
        }
    }
}

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
