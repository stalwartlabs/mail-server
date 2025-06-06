/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};

use arc_swap::ArcSwap;
use pwhash::sha512_crypt;
use store::{
    Stores,
    rand::{Rng, distr::Alphanumeric, rng},
};
use tokio::sync::{Notify, Semaphore, mpsc};
use utils::{
    Semver, UnwrapFailure,
    config::{Config, ConfigKey},
    failed,
};

use crate::{
    Caches, Core, Data, IPC_CHANNEL_BUFFER, Inner, Ipc,
    config::{network::AsnGeoLookupConfig, server::Listeners, telemetry::Telemetry},
    core::BuildServer,
    ipc::{BroadcastEvent, HousekeeperEvent, QueueEvent, ReportingEvent, StateEvent},
};

use super::{
    WEBADMIN_KEY,
    backup::BackupParams,
    config::{ConfigManager, Patterns},
    console::store_console,
};

pub struct BootManager {
    pub config: Config,
    pub inner: Arc<Inner>,
    pub servers: Listeners,
    pub ipc_rxs: IpcReceivers,
}

pub struct IpcReceivers {
    pub state_rx: Option<mpsc::Receiver<StateEvent>>,
    pub housekeeper_rx: Option<mpsc::Receiver<HousekeeperEvent>>,
    pub queue_rx: Option<mpsc::Receiver<QueueEvent>>,
    pub report_rx: Option<mpsc::Receiver<ReportingEvent>>,
    pub broadcast_rx: Option<mpsc::Receiver<BroadcastEvent>>,
}

const HELP: &str = concat!(
    "Stalwart Server v",
    env!("CARGO_PKG_VERSION"),
    r#"

Usage: stalwart [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -o, --console                    Open the store console
  -I, --init <PATH>                Initialize a new server at a specific path
  -h, --help                       Print help
  -V, --version                    Print version
"#
);

#[derive(PartialEq, Eq)]
enum StoreOp {
    Export(BackupParams),
    Import(PathBuf),
    Console,
    None,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut import_export = StoreOp::None;

        if config_path.is_none() {
            let mut args = std::env::args().skip(1);

            while let Some(arg) = args.next().and_then(|arg| {
                arg.strip_prefix("--")
                    .or_else(|| arg.strip_prefix('-'))
                    .map(|arg| arg.to_string())
            }) {
                let (key, value) = if let Some((key, value)) = arg.split_once('=') {
                    (key.to_string(), Some(value.trim().to_string()))
                } else {
                    (arg, args.next())
                };

                match (key.as_str(), value) {
                    ("help" | "h", _) => {
                        eprintln!("{HELP}");
                        std::process::exit(0);
                    }
                    ("version" | "V", _) => {
                        println!("{}", env!("CARGO_PKG_VERSION"));
                        std::process::exit(0);
                    }
                    ("config" | "c", Some(value)) => {
                        config_path = Some(value);
                    }
                    ("init" | "I", Some(value)) => {
                        quickstart(value);
                        std::process::exit(0);
                    }
                    ("export" | "e", Some(value)) => {
                        import_export = StoreOp::Export(BackupParams::new(value.into()));
                    }
                    ("import" | "i", Some(value)) => {
                        import_export = StoreOp::Import(value.into());
                    }
                    ("console" | "o", None) => {
                        import_export = StoreOp::Console;
                    }
                    (_, None) => {
                        failed(&format!("Unrecognized command '{key}', try '--help'."));
                    }
                    (_, Some(_)) => failed(&format!(
                        "Missing value for argument '{key}', try '--help'."
                    )),
                }
            }

            if config_path.is_none() {
                if import_export == StoreOp::None {
                    eprintln!("{HELP}");
                } else {
                    eprintln!("Missing '--config' argument for import/export.")
                }
                std::process::exit(0);
            }
        }

        // Read main configuration file
        let cfg_local_path = PathBuf::from(config_path.unwrap());
        let mut config = Config::default();
        match std::fs::read_to_string(&cfg_local_path) {
            Ok(value) => {
                config.parse(&value).failed("Invalid configuration file");
            }
            Err(err) => {
                config.new_build_error("*", format!("Could not read configuration file: {err}"));
            }
        }
        let cfg_local = config.keys.clone();

        // Resolve environment macros
        config.resolve_macros(&["env"]).await;

        // Parser servers
        let mut servers = Listeners::parse(&mut config);

        // Bind ports and drop privileges
        servers.bind_and_drop_priv(&mut config);

        // Resolve file and configuration macros
        config.resolve_macros(&["file", "cfg"]).await;

        // Load stores
        let mut stores = Stores::parse(&mut config).await;
        let local_patterns = Patterns::parse(&mut config);

        // Build local keys and warn about database keys defined in the local configuration
        let mut warn_keys = Vec::new();
        for key in config.keys.keys() {
            if !local_patterns.is_local_key(key) {
                warn_keys.push(key.clone());
            }
        }
        for warn_key in warn_keys {
            config.new_build_warning(
                warn_key,
                concat!(
                    "Database key defined in local configuration, this might cause issues. ",
                    "See https://stalw.art/docs/configuration/overview/#loc",
                    "al-and-database-settings"
                ),
            );
        }

        // Build manager
        let manager = ConfigManager {
            cfg_local: ArcSwap::from_pointee(cfg_local),
            cfg_local_path,
            cfg_local_patterns: local_patterns.into(),
            cfg_store: config
                .value("storage.data")
                .and_then(|id| stores.stores.get(id))
                .cloned()
                .unwrap_or_default(),
        };

        // Extend configuration with settings stored in the db
        if !manager.cfg_store.is_none() {
            for (key, value) in manager
                .db_list("", false)
                .await
                .failed("Failed to read database configuration")
            {
                if manager.cfg_local_patterns.is_local_key(&key) {
                    config.new_build_warning(
                        &key,
                        concat!(
                            "Local key defined in database, this might cause issues. ",
                            "See https://stalw.art/docs/configuration/overview/#loc",
                            "al-and-database-settings"
                        ),
                    );
                }

                config.keys.entry(key).or_insert(value);
            }
        }

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut config, &stores);

        match import_export {
            StoreOp::None => {
                // Add hostname lookup if missing
                let mut insert_keys = Vec::new();

                // Generate an OAuth key if missing
                if config
                    .value("oauth.key")
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    insert_keys.push(ConfigKey::from((
                        "oauth.key",
                        rng()
                            .sample_iter(Alphanumeric)
                            .take(64)
                            .map(char::from)
                            .collect::<String>(),
                    )));
                }

                // Download Spam filter rules if missing
                // TODO remove this check in 1.0
                let update_webadmin = match config.value("version.spam-filter").and_then(|v| {
                    if !v.is_empty() {
                        Some(Semver::try_from(v))
                    } else {
                        None
                    }
                }) {
                    Some(Err(_)) => {
                        let _ = manager.clear_prefix("lookup.spam-").await;
                        let _ = manager
                            .clear_prefix("sieve.trusted.scripts.spam-filter")
                            .await;
                        let _ = manager
                            .clear_prefix("sieve.trusted.scripts.track-replies")
                            .await;
                        let _ = manager.clear_prefix("sieve.trusted.scripts.greylist").await;
                        let _ = manager.clear_prefix("sieve.trusted.scripts.train").await;
                        let _ = manager.clear("version.spam-filter").await;

                        match manager.fetch_spam_rules().await {
                            Ok(external_config) => {
                                trc::event!(
                                    Config(trc::ConfigEvent::ImportExternal),
                                    Version = external_config.version.to_string(),
                                    Id = "spam-filter"
                                );
                                insert_keys.extend(external_config.keys);
                            }
                            Err(err) => {
                                config.new_build_error(
                                    "*",
                                    format!("Failed to fetch spam filter: {err}"),
                                );
                            }
                        }

                        true
                    }
                    Some(Ok(_)) => false,
                    None => {
                        match manager.fetch_spam_rules().await {
                            Ok(external_config) => {
                                trc::event!(
                                    Config(trc::ConfigEvent::ImportExternal),
                                    Version = external_config.version.to_string(),
                                    Id = "spam-filter"
                                );
                                insert_keys.extend(external_config.keys);
                            }
                            Err(err) => {
                                config.new_build_error(
                                    "*",
                                    format!("Failed to fetch spam filter: {err}"),
                                );
                            }
                        }

                        // Add default settings
                        for key in [
                            ("queue.quota.size.messages", "100000"),
                            ("queue.quota.size.size", "10737418240"),
                            ("queue.quota.size.enable", "true"),
                            ("queue.limiter.inbound.ip.key", "remote_ip"),
                            ("queue.limiter.inbound.ip.rate", "5/1s"),
                            ("queue.limiter.inbound.ip.enable", "true"),
                            ("queue.limiter.inbound.sender.key.0", "sender_domain"),
                            ("queue.limiter.inbound.sender.key.1", "rcpt"),
                            ("queue.limiter.inbound.sender.rate", "25/1h"),
                            ("queue.limiter.inbound.sender.enable", "true"),
                            ("report.analysis.addresses", "postmaster@*"),
                        ] {
                            insert_keys.push(ConfigKey::from(key));
                        }

                        false
                    }
                };

                // Download webadmin if missing
                if let Some(blob_store) = config
                    .value("storage.blob")
                    .and_then(|id| stores.blob_stores.get(id))
                {
                    match blob_store.get_blob(WEBADMIN_KEY, 0..usize::MAX).await {
                        Ok(Some(_)) => (),
                        Ok(None) => match manager.fetch_resource("webadmin").await {
                            Ok(bytes) => match blob_store.put_blob(WEBADMIN_KEY, &bytes).await {
                                Ok(_) => {
                                    trc::event!(
                                        Resource(trc::ResourceEvent::DownloadExternal),
                                        Id = "webadmin"
                                    );
                                }
                                Err(err) => {
                                    config.new_build_error(
                                        "*",
                                        format!("Failed to store webadmin blob: {err}"),
                                    );
                                }
                            },
                            Err(err) => {
                                config.new_build_error(
                                    "*",
                                    format!("Failed to download webadmin: {err}"),
                                );
                            }
                        },
                        Err(err) => config
                            .new_build_error("*", format!("Failed to access webadmin blob: {err}")),
                    }
                }

                // Add missing settings
                if !insert_keys.is_empty() {
                    for item in &insert_keys {
                        config.keys.insert(item.key.clone(), item.value.clone());
                    }

                    if let Err(err) = manager.set(insert_keys, true).await {
                        config
                            .new_build_error("*", format!("Failed to update configuration: {err}"));
                    }
                }

                // Parse in-memory stores
                stores.parse_in_memory(&mut config, false).await;

                // Parse settings
                let core = Box::pin(Core::parse(&mut config, stores, manager)).await;

                // Parse data
                let data = Data::parse(&mut config);

                // Parse caches
                let cache = Caches::parse(&mut config);

                // Enable telemetry
                #[cfg(feature = "enterprise")]
                telemetry.enable(core.is_enterprise_edition());
                #[cfg(not(feature = "enterprise"))]
                telemetry.enable(false);

                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Version = env!("CARGO_PKG_VERSION"),
                );

                // Webadmin auto-update
                if update_webadmin
                    || config
                        .property_or_default::<bool>("webadmin.auto-update", "false")
                        .unwrap_or_default()
                {
                    if let Err(err) = data.webadmin.update(&core).await {
                        trc::event!(
                            Resource(trc::ResourceEvent::Error),
                            Details = "Failed to update webadmin",
                            CausedBy = err
                        );
                    }
                }

                // Spam filter auto-update
                if config
                    .property_or_default::<bool>("spam-filter.auto-update", "false")
                    .unwrap_or_default()
                {
                    if let Err(err) = core.storage.config.update_spam_rules(false, false).await {
                        trc::event!(
                            Resource(trc::ResourceEvent::Error),
                            Details = "Failed to update spam-filter",
                            CausedBy = err
                        );
                    }
                }

                // Build shared inner
                let has_remote_asn = matches!(
                    core.network.asn_geo_lookup,
                    AsnGeoLookupConfig::Resource { .. }
                );
                let (ipc, ipc_rxs) = build_ipc(&mut config, !core.storage.pubsub.is_none());
                let inner = Arc::new(Inner {
                    shared_core: ArcSwap::from_pointee(core),
                    data,
                    ipc,
                    cache,
                });

                // Fetch ASN database
                if has_remote_asn {
                    inner
                        .build_server()
                        .lookup_asn_country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                        .await;
                }

                // Parse TCP acceptors
                servers.parse_tcp_acceptors(&mut config, inner.clone());

                BootManager {
                    inner,
                    config,
                    servers,
                    ipc_rxs,
                }
            }
            StoreOp::Export(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and backup
                Box::pin(Core::parse(&mut config, stores, manager))
                    .await
                    .backup(path)
                    .await;
                std::process::exit(0);
            }
            StoreOp::Import(path) => {
                // Enable telemetry
                telemetry.enable(false);

                // Parse settings and restore
                Box::pin(Core::parse(&mut config, stores, manager))
                    .await
                    .restore(path)
                    .await;
                std::process::exit(0);
            }
            StoreOp::Console => {
                // Store console
                store_console(
                    Box::pin(Core::parse(&mut config, stores, manager))
                        .await
                        .storage
                        .data,
                )
                .await;
                std::process::exit(0);
            }
        }
    }
}

pub fn build_ipc(config: &mut Config, has_pubsub: bool) -> (Ipc, IpcReceivers) {
    // Build ipc receivers
    let (state_tx, state_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (housekeeper_tx, housekeeper_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (queue_tx, queue_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (report_tx, report_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    let (broadcast_tx, broadcast_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);
    (
        Ipc {
            state_tx,
            housekeeper_tx,
            queue_tx,
            report_tx,
            broadcast_tx: has_pubsub.then_some(broadcast_tx),
            task_tx: Arc::new(Notify::new()),
            local_delivery_sm: Arc::new(Semaphore::new(
                config
                    .property_or_default::<usize>("queue.threads.local", "10")
                    .unwrap_or(10)
                    .max(1),
            )),
        },
        IpcReceivers {
            state_rx: Some(state_rx),
            housekeeper_rx: Some(housekeeper_rx),
            queue_rx: Some(queue_rx),
            report_rx: Some(report_rx),
            broadcast_rx: has_pubsub.then_some(broadcast_rx),
        },
    )
}

fn quickstart(path: impl Into<PathBuf>) {
    let path = path.into();

    if !path.exists() {
        std::fs::create_dir_all(&path).failed("Failed to create directory");
    }

    for dir in &["etc", "data", "logs"] {
        let sub_path = path.join(dir);
        if !sub_path.exists() {
            std::fs::create_dir(sub_path).failed(&format!("Failed to create {dir} directory"));
        }
    }

    let admin_pass = std::env::var("STALWART_ADMIN_PASSWORD").unwrap_or_else(|_| {
        rng()
            .sample_iter(Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
    });

    std::fs::write(
        path.join("etc").join("config.toml"),
        QUICKSTART_CONFIG
            .replace("_P_", &path.to_string_lossy())
            .replace("_S_", &sha512_crypt::hash(&admin_pass).unwrap()),
    )
    .failed("Failed to write configuration file");

    eprintln!(
        "✅ Configuration file written to {}/etc/config.toml",
        path.to_string_lossy()
    );
    eprintln!("🔑 Your administrator account is 'admin' with password '{admin_pass}'.");
}

#[cfg(not(feature = "foundation"))]
const QUICKSTART_CONFIG: &str = r#"[server.listener.smtp]
bind = "[::]:25"
protocol = "smtp"

[server.listener.submission]
bind = "[::]:587"
protocol = "smtp"

[server.listener.submissions]
bind = "[::]:465"
protocol = "smtp"
tls.implicit = true

[server.listener.imap]
bind = "[::]:143"
protocol = "imap"

[server.listener.imaptls]
bind = "[::]:993"
protocol = "imap"
tls.implicit = true

[server.listener.pop3]
bind = "[::]:110"
protocol = "pop3"

[server.listener.pop3s]
bind = "[::]:995"
protocol = "pop3"
tls.implicit = true

[server.listener.sieve]
bind = "[::]:4190"
protocol = "managesieve"

[server.listener.https]
protocol = "http"
bind = "[::]:443"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "internal"

[store.rocksdb]
type = "rocksdb"
path = "_P_/data"
compression = "lz4"

[directory.internal]
type = "internal"
store = "rocksdb"

[tracer.log]
type = "log"
level = "info"
path = "_P_/logs"
prefix = "stalwart.log"
rotate = "daily"
ansi = false
enable = true

[authentication.fallback-admin]
user = "admin"
secret = "_S_"
"#;

#[cfg(feature = "foundation")]
const QUICKSTART_CONFIG: &str = r#"[server.listener.smtp]
bind = "[::]:25"
protocol = "smtp"

[server.listener.submission]
bind = "[::]:587"
protocol = "smtp"

[server.listener.submissions]
bind = "[::]:465"
protocol = "smtp"
tls.implicit = true

[server.listener.imap]
bind = "[::]:143"
protocol = "imap"

[server.listener.imaptls]
bind = "[::]:993"
protocol = "imap"
tls.implicit = true

[server.listener.pop3]
bind = "[::]:110"
protocol = "pop3"

[server.listener.pop3s]
bind = "[::]:995"
protocol = "pop3"
tls.implicit = true

[server.listener.sieve]
bind = "[::]:4190"
protocol = "managesieve"

[server.listener.https]
protocol = "http"
bind = "[::]:443"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[storage]
data = "foundation-db"
fts = "foundation-db"
blob = "foundation-db"
lookup = "foundation-db"
directory = "internal"

[store.foundation-db]
type = "foundationdb"
compression = "lz4"

[directory.internal]
type = "internal"
store = "foundation-db"

[tracer.log]
type = "log"
level = "info"
path = "_P_/logs"
prefix = "stalwart.log"
rotate = "daily"
ansi = false
enable = true

[authentication.fallback-admin]
user = "admin"
secret = "_S_"
"#;
