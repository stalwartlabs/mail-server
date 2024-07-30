/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::path::PathBuf;

use arc_swap::ArcSwap;
use pwhash::sha512_crypt;
use store::{
    rand::{distributions::Alphanumeric, thread_rng, Rng},
    Stores,
};
use utils::{
    config::{Config, ConfigKey},
    failed, UnwrapFailure,
};

use crate::{
    config::{server::Servers, tracers::Tracers},
    Core, SharedCore,
};

use super::{
    config::{ConfigManager, Patterns},
    WEBADMIN_KEY,
};

pub struct BootManager {
    pub config: Config,
    pub core: SharedCore,
    pub servers: Servers,
}

const HELP: &str = r#"Stalwart Mail Server

Usage: stalwart-mail [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -e, --export <PATH>              Export all store data to a specific path
  -i, --import <PATH>              Import store data from a specific path
  -I, --init <PATH>                Initialize a new server at a specific path
  -h, --help                       Print help
  -V, --version                    Print version
"#;

#[derive(PartialEq, Eq)]
enum ImportExport {
    Export(PathBuf),
    Import(PathBuf),
    None,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut import_export = ImportExport::None;

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
                        import_export = ImportExport::Export(value.into());
                    }
                    ("import" | "i", Some(value)) => {
                        import_export = ImportExport::Import(value.into());
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
                if import_export == ImportExport::None {
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
        let mut servers = Servers::parse(&mut config);

        // Bind ports and drop privileges
        servers.bind_and_drop_priv(&mut config);

        // Resolve file and configuration macros
        config.resolve_macros(&["file", "cfg"]).await;

        // Load stores
        let mut stores = Stores::parse(&mut config).await;

        // Build manager
        let manager = ConfigManager {
            cfg_local: ArcSwap::from_pointee(cfg_local),
            cfg_local_path,
            cfg_local_patterns: Patterns::parse(&mut config).into(),
            cfg_store: config
                .value("storage.data")
                .and_then(|id| stores.stores.get(id))
                .cloned()
                .unwrap_or_default(),
        };

        // Extend configuration with settings stored in the db
        if !manager.cfg_store.is_none() {
            manager
                .extend_config(&mut config, "")
                .await
                .failed("Failed to read configuration");
        }

        // Enable tracing
        Tracers::parse(&mut config).enable();

        match import_export {
            ImportExport::None => {
                trc::event!(
                    Server(trc::ServerEvent::Startup),
                    Version = env!("CARGO_PKG_VERSION"),
                );

                // Add hostname lookup if missing
                let mut insert_keys = Vec::new();
                if config
                    .value("lookup.default.hostname")
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    insert_keys.push(ConfigKey::from((
                        "lookup.default.hostname",
                        hostname::get()
                            .map(|v| v.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| "localhost".to_string()),
                    )));
                }

                // Generate an OAuth key if missing
                if config
                    .value("oauth.key")
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    insert_keys.push(ConfigKey::from((
                        "oauth.key",
                        thread_rng()
                            .sample_iter(Alphanumeric)
                            .take(64)
                            .map(char::from)
                            .collect::<String>(),
                    )));
                }

                // Generate a Cluster encryption key if missing
                if config
                    .value("cluster.key")
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    insert_keys.push(ConfigKey::from((
                        "cluster.key",
                        thread_rng()
                            .sample_iter(Alphanumeric)
                            .take(64)
                            .map(char::from)
                            .collect::<String>(),
                    )));
                }

                // Download SPAM filters if missing
                if config
                    .value("version.spam-filter")
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    match manager.fetch_config_resource("spam-filter").await {
                        Ok(external_config) => {
                            trc::event!(
                                Config(trc::ConfigEvent::ImportExternal),
                                Version = external_config.version,
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
                        ("queue.throttle.rcpt.key", "rcpt_domain"),
                        ("queue.throttle.rcpt.concurrency", "5"),
                        ("queue.throttle.rcpt.enable", "true"),
                        ("session.throttle.ip.key", "remote_ip"),
                        ("session.throttle.ip.concurrency", "5"),
                        ("session.throttle.ip.enable", "true"),
                        ("session.throttle.sender.key.0", "sender_domain"),
                        ("session.throttle.sender.key.1", "rcpt"),
                        ("session.throttle.sender.rate", "25/1h"),
                        ("session.throttle.sender.enable", "true"),
                        ("report.analysis.addresses", "postmaster@*"),
                    ] {
                        insert_keys.push(ConfigKey::from(key));
                    }
                }

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

                    if let Err(err) = manager.set(insert_keys).await {
                        config
                            .new_build_error("*", format!("Failed to update configuration: {err}"));
                    }
                }

                // Parse lookup stores
                stores.parse_lookups(&mut config).await;

                // Parse settings and build shared core
                let core = Core::parse(&mut config, stores, manager)
                    .await
                    .into_shared();

                // Parse TCP acceptors
                servers.parse_tcp_acceptors(&mut config, core.clone());

                BootManager {
                    core,
                    config,
                    servers,
                }
            }
            ImportExport::Export(path) => {
                Core::parse(&mut config, stores, manager)
                    .await
                    .backup(path)
                    .await;
                std::process::exit(0);
            }
            ImportExport::Import(path) => {
                Core::parse(&mut config, stores, manager)
                    .await
                    .restore(path)
                    .await;
                std::process::exit(0);
            }
        }
    }
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
        thread_rng()
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
