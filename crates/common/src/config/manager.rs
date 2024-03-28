use std::{
    collections::{btree_map::Entry, BTreeMap},
    path::PathBuf,
    sync::Arc,
};

use ahash::AHashSet;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use store::{
    write::{BatchBuilder, ValueClass},
    Deserialize, IterateParams, Store, Stores, ValueKey,
};
use tracing_appender::non_blocking::WorkerGuard;
use utils::{
    config::{ipmask::IpAddrOrMask, utils::ParseValue, Config, ConfigKey},
    failed,
    glob::GlobPattern,
    UnwrapFailure,
};

use crate::{listener::blocked::BLOCKED_IP_KEY, Core, SharedCore};

use super::{
    server::{tls::parse_certificates, Servers},
    tracers::Tracers,
};

#[derive(Default)]
pub struct ConfigManager {
    cfg_local: ArcSwap<BTreeMap<String, String>>,
    cfg_local_path: PathBuf,
    cfg_local_patterns: Arc<Patterns>,
    cfg_store: Store,
}

#[derive(Default)]
pub struct Patterns {
    patterns: Vec<Pattern>,
}

enum Pattern {
    Include(MatchType),
    Exclude(MatchType),
}

pub struct ReloadResult {
    pub config: Config,
    pub new_core: Option<Core>,
}

enum MatchType {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
    Matches(GlobPattern),
    All,
}

pub struct BootManager {
    pub config: Config,
    pub core: SharedCore,
    pub servers: Servers,
    pub guards: Option<Vec<WorkerGuard>>,
}

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();
        let mut found_param = false;

        if config_path.is_none() {
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
        }

        // Read main configuration file
        let cfg_local_path =
            PathBuf::from(config_path.failed("Missing parameter --config=<path-to-config>."));
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

        // Resolve macros
        config.resolve_macros().await;

        // Parser servers
        let mut servers = Servers::parse(&mut config);

        // Bind ports and drop privileges
        servers.bind_and_drop_priv(&mut config);

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
            guards: Tracers::parse(&mut config).enable(&mut config),
            config,
            servers,
        }
    }
}

impl ConfigManager {
    pub async fn build_config(&self, prefix: &str) -> store::Result<Config> {
        let mut config = Config {
            keys: self.cfg_local.load().as_ref().clone(),
            ..Default::default()
        };
        config.resolve_macros().await;
        self.extend_config(&mut config, prefix)
            .await
            .map(|_| config)
    }

    async fn extend_config(&self, config: &mut Config, prefix: &str) -> store::Result<()> {
        for (key, value) in self.db_list(prefix, false).await? {
            config.keys.entry(key).or_insert(value);
        }

        Ok(())
    }

    pub async fn get(&self, key: impl AsRef<str>) -> store::Result<Option<String>> {
        let key = key.as_ref();
        match self.cfg_local.load().get(key) {
            Some(value) => Ok(Some(value.to_string())),
            None => {
                self.cfg_store
                    .get_value(ValueKey::from(ValueClass::Config(
                        key.to_string().into_bytes(),
                    )))
                    .await
            }
        }
    }

    pub async fn list(
        &self,
        prefix: &str,
        strip_prefix: bool,
    ) -> store::Result<Vec<(String, String)>> {
        let mut results = self.db_list(prefix, strip_prefix).await?;
        for (key, value) in self.cfg_local.load().iter() {
            if !strip_prefix || prefix.is_empty() {
                results.push((key.clone(), value.clone()));
            } else if key.starts_with(prefix) {
                if let Some(key) = key.strip_prefix(prefix) {
                    results.push((key.to_string(), value.clone()));
                }
            }
        }

        Ok(results)
    }

    async fn db_list(
        &self,
        prefix: &str,
        strip_prefix: bool,
    ) -> store::Result<Vec<(String, String)>> {
        let key = prefix.as_bytes();
        let from_key = ValueKey::from(ValueClass::Config(key.to_vec()));
        let to_key = ValueKey::from(ValueClass::Config(
            key.iter()
                .copied()
                .chain([u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX])
                .collect::<Vec<_>>(),
        ));
        let mut results = Vec::new();
        let patterns = self.cfg_local_patterns.clone();
        self.cfg_store
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let mut key =
                        std::str::from_utf8(key.get(1..).unwrap_or_default()).map_err(|_| {
                            store::Error::InternalError(
                                "Failed to deserialize config key".to_string(),
                            )
                        })?;

                    if !patterns.is_local_key(key) {
                        if strip_prefix && !prefix.is_empty() {
                            key = key.strip_prefix(prefix).unwrap_or(key);
                        }

                        results.push((key.to_string(), String::deserialize(value)?));
                    }

                    Ok(true)
                },
            )
            .await?;

        Ok(results)
    }

    pub async fn set(&self, keys: impl IntoIterator<Item = ConfigKey>) -> store::Result<()> {
        let mut batch = BatchBuilder::new();
        let mut local_batch = Vec::new();

        for key in keys {
            if self.cfg_local_patterns.is_local_key(&key.key) {
                local_batch.push(key);
            } else {
                batch.set(ValueClass::Config(key.key.into_bytes()), key.value);
            }
        }

        if !batch.is_empty() {
            self.cfg_store.write(batch.build()).await?;
        }

        if !local_batch.is_empty() {
            let mut local = self.cfg_local.load().as_ref().clone();
            let mut has_changes = false;

            for key in local_batch {
                match local.entry(key.key) {
                    Entry::Vacant(v) => {
                        v.insert(key.value);
                        has_changes = true;
                    }
                    Entry::Occupied(mut v) => {
                        if v.get() != &key.value {
                            v.insert(key.value);
                            has_changes = true;
                        }
                    }
                }
            }
            if has_changes {
                self.update_local(local).await?;
            }
        }

        Ok(())
    }

    pub async fn clear(&self, key: impl AsRef<str>) -> store::Result<()> {
        let key = key.as_ref();

        if self.cfg_local_patterns.is_local_key(key) {
            let mut local = self.cfg_local.load().as_ref().clone();
            if local.remove(key).is_some() {
                self.update_local(local).await
            } else {
                Ok(())
            }
        } else {
            let mut batch = BatchBuilder::new();
            batch.clear(ValueClass::Config(key.to_string().into_bytes()));
            self.cfg_store.write(batch.build()).await.map(|_| ())
        }
    }

    pub async fn clear_prefix(&self, key: impl AsRef<str>) -> store::Result<()> {
        let key = key.as_ref();

        // Delete local keys
        let local = self.cfg_local.load();
        if local.keys().any(|k| k.starts_with(key)) {
            let mut local = local.as_ref().clone();
            local.retain(|k, _| !k.starts_with(key));
            self.update_local(local).await?;
        }

        // Delete db keys
        self.cfg_store
            .delete_range(
                ValueKey::from(ValueClass::Config(key.as_bytes().to_vec())),
                ValueKey::from(ValueClass::Config(
                    key.as_bytes()
                        .iter()
                        .copied()
                        .chain([u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX])
                        .collect::<Vec<_>>(),
                )),
            )
            .await
    }

    async fn update_local(&self, map: BTreeMap<String, String>) -> store::Result<()> {
        let mut cfg_text = String::with_capacity(1024);
        for (key, value) in &map {
            cfg_text.push_str(key);
            cfg_text.push_str(" = ");
            if value == "true" || value == "false" || value.parse::<f64>().is_ok() {
                cfg_text.push_str(value);
            } else {
                cfg_text.push('"');
                cfg_text.push_str(&value.replace('"', "\\\""));
                cfg_text.push('"');
            }

            cfg_text.push_str(value);
            cfg_text.push('\n');
        }

        self.cfg_local.store(map.into());

        tokio::fs::write(&self.cfg_local_path, cfg_text)
            .await
            .map_err(|err| {
                store::Error::InternalError(format!(
                    "Failed to write local configuration file: {err}"
                ))
            })
    }
}

impl Core {
    pub async fn reload_blocked_ips(&self) -> store::Result<ReloadResult> {
        let mut ip_addresses = AHashSet::new();
        let mut config = self.storage.config.build_config(BLOCKED_IP_KEY).await?;

        for ip in config
            .set_values(BLOCKED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(_)) => {}
                Err(err) => {
                    config.new_parse_error(BLOCKED_IP_KEY, err);
                }
            }
        }

        *self.network.blocked_ips.ip_addresses.write() = ip_addresses;

        Ok(config.into())
    }

    pub async fn reload_certificates(&self) -> store::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("certificate").await?;
        let mut certificates = self.tls.certificates.load().as_ref().clone();

        parse_certificates(&mut config, &mut certificates, &mut Default::default());

        self.tls.certificates.store(certificates.into());

        Ok(config.into())
    }

    pub async fn reload_lookups(&self) -> store::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("certificate").await?;
        let mut stores = Stores::default();
        stores.parse_memory_stores(&mut config);

        let mut core = self.clone();
        for (id, store) in stores.lookup_stores {
            core.storage.lookups.insert(id, store);
        }

        Ok(ReloadResult {
            config,
            new_core: core.into(),
        })
    }

    pub async fn reload(&self) -> store::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("").await?;

        // Parse tracers
        Tracers::parse(&mut config);

        // Load stores
        let mut stores = Stores {
            stores: self.storage.stores.clone(),
            blob_stores: self.storage.blobs.clone(),
            fts_stores: self.storage.ftss.clone(),
            lookup_stores: self.storage.lookups.clone(),
            purge_schedules: Default::default(),
        };
        stores.parse_stores(&mut config).await;
        stores.parse_lookups(&mut config).await;
        if !config.errors.is_empty() {
            return Ok(config.into());
        }

        // Build manager
        let manager = ConfigManager {
            cfg_local: ArcSwap::from_pointee(self.storage.config.cfg_local.load().as_ref().clone()),
            cfg_local_path: self.storage.config.cfg_local_path.clone(),
            cfg_local_patterns: Patterns::parse(&mut config).into(),
            cfg_store: config
                .value("storage.data")
                .and_then(|id| stores.stores.get(id))
                .cloned()
                .unwrap_or_default(),
        };

        // Parse settings and build shared core
        let mut core = Core::parse(&mut config, stores, manager).await;
        if !config.errors.is_empty() {
            return Ok(config.into());
        }
        // Transfer Sieve cache
        core.sieve.bayes_cache = self.sieve.bayes_cache.clone();
        core.sieve.remote_lists = RwLock::new(self.sieve.remote_lists.read().clone());

        // Copy ACME certificates
        let mut certificates = core.tls.certificates.load().as_ref().clone();
        for (cert_id, cert) in self.tls.certificates.load().iter() {
            certificates
                .entry(cert_id.to_string())
                .or_insert(cert.clone());
        }
        core.tls.certificates.store(certificates.into());

        // Parser servers
        let mut servers = Servers::parse(&mut config);
        servers.parse_tcp_acceptors(&mut config, core.clone().into_shared());

        Ok(if config.errors.is_empty() {
            ReloadResult {
                config,
                new_core: core.into(),
            }
        } else {
            config.into()
        })
    }
}

impl Patterns {
    pub fn parse(config: &mut Config) -> Self {
        let mut cfg_local_patterns = Vec::new();
        for (key, value) in &config.keys {
            if !key.starts_with("config.local-keys") {
                if cfg_local_patterns.is_empty() {
                    continue;
                } else {
                    break;
                }
            };
            let value = value.trim();
            let (value, is_include) = value
                .strip_prefix('!')
                .map_or((value, true), |value| (value, false));
            let value = value.trim().to_ascii_lowercase();
            if value.is_empty() {
                continue;
            }
            let match_type = if value == "*" {
                MatchType::All
            } else if let Some(value) = value.strip_prefix('*') {
                MatchType::StartsWith(value.to_string())
            } else if let Some(value) = value.strip_suffix('*') {
                MatchType::EndsWith(value.to_string())
            } else if value.contains('*') {
                MatchType::Matches(GlobPattern::compile(&value, false))
            } else {
                MatchType::Equal(value.to_string())
            };

            cfg_local_patterns.push(if is_include {
                Pattern::Include(match_type)
            } else {
                Pattern::Exclude(match_type)
            });
        }
        if cfg_local_patterns.is_empty() {
            cfg_local_patterns = vec![
                Pattern::Include(MatchType::StartsWith("store.".to_string())),
                Pattern::Include(MatchType::StartsWith("server.listener.".to_string())),
                Pattern::Include(MatchType::StartsWith("server.socket.".to_string())),
                Pattern::Include(MatchType::StartsWith("server.tls.".to_string())),
                Pattern::Include(MatchType::Equal("cluster.node-id".to_string())),
                Pattern::Include(MatchType::Equal("storage.data".to_string())),
                Pattern::Include(MatchType::Equal("storage.blob".to_string())),
                Pattern::Include(MatchType::Equal("storage.lookup".to_string())),
                Pattern::Include(MatchType::Equal("storage.fts".to_string())),
                Pattern::Include(MatchType::Equal("server.run-as.user".to_string())),
                Pattern::Include(MatchType::Equal("server.run-as.group".to_string())),
                Pattern::Exclude(MatchType::Matches(GlobPattern::compile(
                    "store.*.query.*",
                    false,
                ))),
            ];
        }

        Patterns {
            patterns: cfg_local_patterns,
        }
    }

    pub fn is_local_key(&self, key: &str) -> bool {
        let mut is_local = false;

        for pattern in &self.patterns {
            match pattern {
                Pattern::Include(pattern) => {
                    if !is_local && pattern.matches(key) {
                        is_local = true;
                    }
                }
                Pattern::Exclude(pattern) => {
                    if pattern.matches(key) {
                        return false;
                    }
                }
            }
        }

        is_local
    }
}

impl MatchType {
    fn matches(&self, value: &str) -> bool {
        match self {
            MatchType::Equal(pattern) => value == pattern,
            MatchType::StartsWith(pattern) => value.starts_with(pattern),
            MatchType::EndsWith(pattern) => value.ends_with(pattern),
            MatchType::Matches(pattern) => pattern.matches(value),
            MatchType::All => true,
        }
    }
}

impl Clone for ConfigManager {
    fn clone(&self) -> Self {
        Self {
            cfg_local: ArcSwap::from_pointee(self.cfg_local.load().as_ref().clone()),
            cfg_local_path: self.cfg_local_path.clone(),
            cfg_local_patterns: self.cfg_local_patterns.clone(),
            cfg_store: self.cfg_store.clone(),
        }
    }
}

impl From<Config> for ReloadResult {
    fn from(config: Config) -> Self {
        Self {
            config,
            new_core: None,
        }
    }
}
