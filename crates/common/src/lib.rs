use std::{net::IpAddr, sync::Arc};

use ahash::AHashMap;
use config::{
    imap::ImapConfig,
    jmap::settings::JmapConfig,
    scripts::Scripting,
    server::Server,
    smtp::{
        auth::{ArcSealer, DkimSigner},
        queue::RelayHost,
        SmtpConfig,
    },
    storage::Storage,
    tracers::{OtelTracer, Tracer, Tracers},
};
use directory::{Directory, Principal, QueryBy};
use expr::if_block::IfBlock;
use listener::{acme::AcmeManager, blocked::BlockedIps, tls::Certificate};
use mail_send::Credentials;
use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    trace::{self, Sampler},
    Resource,
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use sieve::Sieve;
use store::LookupStore;
use tracing::{level_filters::LevelFilter, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub mod addresses;
pub mod config;
pub mod expr;
pub mod listener;
pub mod scripts;

pub static USER_AGENT: &str = concat!("StalwartMail/", env!("CARGO_PKG_VERSION"),);
pub static DAEMON_NAME: &str = concat!("Stalwart Mail Server v", env!("CARGO_PKG_VERSION"),);

pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub smtp: SmtpConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
}

pub struct Network {
    pub blocked_ips: BlockedIps,
    pub hostname: IfBlock,
    pub url: IfBlock,
}

pub struct ConfigBuilder {
    pub servers: Vec<Server>,
    pub certificates: AHashMap<String, Arc<Certificate>>,
    pub certificates_sni: AHashMap<String, Arc<Certificate>>,
    pub acme_managers: AHashMap<String, Arc<AcmeManager>>,
    pub tracers: Vec<Tracer>,
    pub core: Core,
}

pub enum AuthResult<T> {
    Success(T),
    Failure,
    Banned,
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

impl Core {
    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str) -> &Arc<Directory> {
        self.storage.directories.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_directory",
                event = "error",
                directory = name,
                "Directory not found, using default."
            );

            &self.storage.directory
        })
    }

    pub fn get_lookup_store(&self, name: &str) -> &LookupStore {
        self.storage.lookups.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_lookup_store",
                event = "error",
                directory = name,
                "Store not found, using default."
            );

            &self.storage.lookup
        })
    }

    pub fn get_arc_sealer(&self, name: &str) -> Option<&ArcSealer> {
        self.smtp
            .mail_auth
            .sealers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_arc_sealer",
                    event = "error",
                    name = name,
                    "Arc sealer not found."
                );

                None
            })
    }

    pub fn get_dkim_signer(&self, name: &str) -> Option<&DkimSigner> {
        self.smtp
            .mail_auth
            .signers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_dkim_signer",
                    event = "error",
                    name = name,
                    "DKIM signer not found."
                );

                None
            })
    }

    pub fn get_sieve_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        self.sieve.scripts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_sieve_script",
                event = "error",
                name = name,
                "Sieve script not found."
            );

            None
        })
    }

    pub fn get_relay_host(&self, name: &str) -> Option<&RelayHost> {
        self.smtp.queue.relay_hosts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_relay_host",
                event = "error",
                name = name,
                "Remote host not found."
            );

            None
        })
    }

    pub async fn authenticate(
        &self,
        directory: &Directory,
        credentials: &Credentials<String>,
        remote_ip: IpAddr,
        return_member_of: bool,
    ) -> directory::Result<AuthResult<Principal<u32>>> {
        if let Some(principal) = directory
            .query(QueryBy::Credentials(credentials), return_member_of)
            .await?
        {
            Ok(AuthResult::Success(principal))
        } else if self.has_fail2ban() {
            let login = match credentials {
                Credentials::Plain { username, .. }
                | Credentials::XOauth2 { username, .. }
                | Credentials::OAuthBearer { token: username } => username,
            };
            if self.is_fail2banned(remote_ip, login.to_string()).await? {
                tracing::info!(
                    context = "directory",
                    event = "fail2ban",
                    remote_ip = ?remote_ip,
                    login = ?login,
                    "IP address blocked after too many failed login attempts",
                );

                Ok(AuthResult::Banned)
            } else {
                Ok(AuthResult::Failure)
            }
        } else {
            Ok(AuthResult::Failure)
        }
    }
}

#[derive(Default)]
pub struct TracerResult {
    pub guards: Vec<WorkerGuard>,
    pub errors: Vec<String>,
}

impl Tracers {
    pub fn enable(self) -> TracerResult {
        let mut layers = Vec::new();
        let mut level = Level::TRACE;

        for tracer in &self.tracers {
            let tracer_level = *match tracer {
                Tracer::Stdout { level, .. }
                | Tracer::Log { level, .. }
                | Tracer::Journal { level }
                | Tracer::Otel { level, .. } => level,
            };

            if tracer_level > level {
                level = tracer_level;
            }
        }

        let mut result = TracerResult::default();
        match EnvFilter::builder().parse(format!(
            "smtp={level},imap={level},jmap={level},store={level},utils={level},directory={level}"
        )) {
            Ok(layer) => {
                layers.push(layer.boxed());
            }
            Err(err) => {
                result
                    .errors
                    .push(format!("Failed to set env filter: {err}"));
            }
        }

        for tracer in self.tracers {
            match tracer {
                Tracer::Stdout { level, ansi } => {
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(ansi)
                            .with_filter(LevelFilter::from_level(level))
                            .boxed(),
                    );
                }
                Tracer::Log {
                    level,
                    appender,
                    ansi,
                } => {
                    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
                    result.guards.push(guard);
                    layers.push(
                        tracing_subscriber::fmt::layer()
                            .with_writer(non_blocking)
                            .with_ansi(ansi)
                            .with_filter(LevelFilter::from_level(level))
                            .boxed(),
                    );
                }
                Tracer::Otel { level, tracer } => {
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
                        Ok(tracer) => {
                            layers.push(
                                tracing_opentelemetry::layer()
                                    .with_tracer(tracer)
                                    .with_filter(LevelFilter::from_level(level))
                                    .boxed(),
                            );
                        }
                        Err(err) => {
                            result
                                .errors
                                .push(format!("Failed to start OpenTelemetry: {err}"));
                        }
                    }
                }
                Tracer::Journal { level } => {
                    #[cfg(unix)]
                    {
                        match tracing_journald::layer() {
                            Ok(layer) => {
                                layers.push(
                                    layer.with_filter(LevelFilter::from_level(level)).boxed(),
                                );
                            }
                            Err(err) => {
                                result
                                    .errors
                                    .push(format!("Failed to start Journald: {err}"));
                            }
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        result
                            .errors
                            .push("Journald is only available on Unix systems.".to_string());
                    }
                }
            }
        }

        if let Err(err) = tracing_subscriber::registry().with(layers).try_init() {
            result
                .errors
                .push(format!("Failed to start tracing: {err}"));
        }

        result
    }
}
