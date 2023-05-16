/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{collections::HashMap, fs, sync::Arc, time::Duration};

use dashmap::DashMap;
use mail_send::smtp::tls::build_tls_connector;
use opentelemetry::{
    sdk::{
        trace::{self, Sampler},
        Resource,
    },
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use stalwart_smtp::{
    config::{Config, ConfigContext, ServerProtocol},
    core::{
        throttle::{ConcurrencyLimiter, ThrottleKeyHasherBuilder},
        Core, QueueCore, ReportCore, SessionCore, TlsConnectors,
    },
    failed,
    queue::{self, manager::SpawnQueue},
    reporting::{self, scheduler::SpawnReport},
    UnwrapFailure,
};
use tokio::sync::{mpsc, watch};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, EnvFilter};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Read configuration parameters
    let config = parse_config();
    let mut config_context = ConfigContext::default();
    config
        .parse_servers(&mut config_context)
        .failed("Configuration error");
    config
        .parse_remote_hosts(&mut config_context)
        .failed("Configuration error");
    config
        .parse_databases(&mut config_context)
        .failed("Configuration error");
    config
        .parse_lists(&mut config_context)
        .failed("Configuration error");
    config
        .parse_signatures(&mut config_context)
        .failed("Configuration error");
    let sieve_config = config
        .parse_sieve(&mut config_context)
        .failed("Configuration error");
    let session_config = config
        .parse_session_config(&config_context)
        .failed("Configuration error");
    let queue_config = config
        .parse_queue(&config_context)
        .failed("Configuration error");
    let mail_auth_config = config
        .parse_mail_auth(&config_context)
        .failed("Configuration error");
    let report_config = config
        .parse_reports(&config_context)
        .failed("Configuration error");

    // Build core
    let (queue_tx, queue_rx) = mpsc::channel(1024);
    let (report_tx, report_rx) = mpsc::channel(1024);
    let core = Arc::new(Core {
        worker_pool: rayon::ThreadPoolBuilder::new()
            .num_threads(
                config
                    .property::<usize>("global.thread-pool")
                    .failed("Failed to parse thread pool size")
                    .filter(|v| *v > 0)
                    .unwrap_or_else(num_cpus::get),
            )
            .build()
            .unwrap(),
        resolvers: config.build_resolvers().failed("Failed to build resolvers"),
        session: SessionCore {
            config: session_config,
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.shared-map.capacity")
                    .failed("Failed to parse shared map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property::<u64>("global.shared-map.shard")
                    .failed("Failed to parse shared map shard amount")
                    .unwrap_or(32)
                    .next_power_of_two() as usize,
            ),
        },
        queue: QueueCore {
            config: queue_config,
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.shared-map.capacity")
                    .failed("Failed to parse shared map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property::<u64>("global.shared-map.shard")
                    .failed("Failed to parse shared map shard amount")
                    .unwrap_or(32)
                    .next_power_of_two() as usize,
            ),
            id_seq: 0.into(),
            quota: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.shared-map.capacity")
                    .failed("Failed to parse shared map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property::<u64>("global.shared-map.shard")
                    .failed("Failed to parse shared map shard amount")
                    .unwrap_or(32)
                    .next_power_of_two() as usize,
            ),
            tx: queue_tx,
            connectors: TlsConnectors {
                pki_verify: build_tls_connector(false),
                dummy_verify: build_tls_connector(true),
            },
        },
        report: ReportCore {
            tx: report_tx,
            config: report_config,
        },
        mail_auth: mail_auth_config,
        sieve: sieve_config,
    });

    // Bind ports before dropping privileges
    for server in &config_context.servers {
        for listener in &server.listeners {
            listener
                .socket
                .bind(listener.addr)
                .failed(&format!("Failed to bind to {}", listener.addr));
        }
    }

    // Drop privileges
    #[cfg(not(target_env = "msvc"))]
    {
        if let Some(run_as_user) = config.value("server.run-as.user") {
            let mut pd = privdrop::PrivDrop::default().user(run_as_user);
            if let Some(run_as_group) = config.value("server.run-as.group") {
                pd = pd.group(run_as_group);
            }
            pd.apply().failed("Failed to drop privileges");
        }
    }

    // Enable tracing
    let _tracer = enable_tracing(&config).failed("Failed to enable tracing");
    tracing::info!(
        "Starting Stalwart SMTP server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Spawn queue manager
    queue_rx.spawn(core.clone(), core.queue.read_queue().await);

    // Spawn report manager
    report_rx.spawn(core.clone(), core.report.read_reports().await);

    // Spawn remote hosts
    for host in config_context.hosts.into_values() {
        if host.lookup {
            host.spawn(&config);
        }
    }

    // Spawn listeners
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for server in config_context.servers {
        match server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server
                .spawn(core.clone(), shutdown_rx.clone())
                .failed("Failed to start listener"),
            ServerProtocol::Http => server
                .spawn_management(core.clone(), shutdown_rx.clone())
                .failed("Failed to start management interface"),
            ServerProtocol::Imap => {
                eprintln!("Invalid protocol 'imap' for listener '{}'.", server.id);
                std::process::exit(0);
            }
        }
    }

    // Wait for shutdown signal
    #[cfg(not(target_env = "msvc"))]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => tracing::debug!("Received SIGTERM."),
            _ = h_int.recv() => tracing::debug!("Received SIGINT."),
        };
    }

    #[cfg(target_env = "msvc")]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("Unable to listen for shutdown signal: {}", err);
            }
        }
    }

    // Shutdown the system
    tracing::info!(
        "Shutting down Stalwart SMTP server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Stop services
    shutdown_tx.send(true).ok();
    core.queue.tx.send(queue::Event::Stop).await.ok();
    core.report.tx.send(reporting::Event::Stop).await.ok();

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

fn enable_tracing(config: &Config) -> stalwart_smtp::config::Result<Option<WorkerGuard>> {
    let level = config.value("global.tracing.level").unwrap_or("info");
    let env_filter = EnvFilter::builder()
        .parse(format!("stalwart_smtp={}", level))
        .failed("Failed to log level");
    match config.value("global.tracing.method").unwrap_or_default() {
        "log" => {
            let path = config.value_require("global.tracing.path")?;
            let prefix = config.value_require("global.tracing.prefix")?;
            let file_appender = match config.value("global.tracing.rotate").unwrap_or("daily") {
                "daily" => tracing_appender::rolling::daily(path, prefix),
                "hourly" => tracing_appender::rolling::hourly(path, prefix),
                "minutely" => tracing_appender::rolling::minutely(path, prefix),
                "never" => tracing_appender::rolling::never(path, prefix),
                rotate => {
                    return Err(format!("Unsupported log rotation strategy {rotate:?}"));
                }
            };

            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            tracing::subscriber::set_global_default(
                tracing_subscriber::FmtSubscriber::builder()
                    .with_env_filter(env_filter)
                    .with_writer(non_blocking)
                    .finish(),
            )
            .failed("Failed to set subscriber");
            Ok(guard.into())
        }
        "stdout" => {
            tracing::subscriber::set_global_default(
                tracing_subscriber::FmtSubscriber::builder()
                    .with_env_filter(env_filter)
                    .finish(),
            )
            .failed("Failed to set subscriber");

            Ok(None)
        }
        "otel" | "open-telemetry" => {
            let tracer = match config.value_require("global.tracing.transport")? {
                "grpc" => {
                    let mut exporter = opentelemetry_otlp::new_exporter().tonic();
                    if let Some(endpoint) = config.value("global.tracing.endpoint") {
                        exporter = exporter.with_endpoint(endpoint);
                    }
                    opentelemetry_otlp::new_pipeline()
                        .tracing()
                        .with_exporter(exporter)
                }
                "http" => {
                    let mut headers = HashMap::new();
                    for (_, value) in config.values("global.tracing.headers") {
                        if let Some((key, value)) = value.split_once(':') {
                            headers.insert(key.trim().to_string(), value.trim().to_string());
                        } else {
                            return Err(format!("Invalid open-telemetry header {value:?}"));
                        }
                    }
                    let mut exporter = opentelemetry_otlp::new_exporter()
                        .http()
                        .with_endpoint(config.value_require("global.tracing.endpoint")?);
                    if !headers.is_empty() {
                        exporter = exporter.with_headers(headers);
                    }
                    opentelemetry_otlp::new_pipeline()
                        .tracing()
                        .with_exporter(exporter)
                }
                transport => {
                    return Err(format!(
                        "Unsupported open-telemetry transport {transport:?}"
                    ));
                }
            }
            .with_trace_config(
                trace::config()
                    .with_resource(Resource::new(vec![
                        KeyValue::new(SERVICE_NAME, "stalwart-smtp".to_string()),
                        KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION").to_string()),
                    ]))
                    .with_sampler(Sampler::AlwaysOn),
            )
            .install_batch(opentelemetry::runtime::Tokio)
            .failed("Failed to create tracer");

            tracing::subscriber::set_global_default(
                tracing_subscriber::Registry::default()
                    .with(tracing_opentelemetry::layer().with_tracer(tracer))
                    .with(env_filter),
            )
            .failed("Failed to set subscriber");

            Ok(None)
        }
        _ => Ok(None),
    }
}

fn parse_config() -> Config {
    let mut config_path = None;
    let mut found_param = false;

    for arg in std::env::args().skip(1) {
        if let Some((key, value)) = arg.split_once('=') {
            if key.starts_with("--config") {
                config_path = value.trim().to_string().into();
                break;
            } else {
                failed(&format!("Invalid command line argument: {key}"));
            }
        } else if found_param {
            config_path = arg.into();
            break;
        } else if arg.starts_with("--config") {
            found_param = true;
        } else {
            failed(&format!("Invalid command line argument: {arg}"));
        }
    }

    Config::parse(
        &fs::read_to_string(config_path.failed("Missing parameter --config=<path-to-config>."))
            .failed("Could not read configuration file"),
    )
    .failed("Invalid configuration file")
}
