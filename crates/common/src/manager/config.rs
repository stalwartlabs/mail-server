/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::{btree_map::Entry, BTreeMap},
    path::PathBuf,
    sync::Arc,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use store::{
    write::{BatchBuilder, ValueClass},
    Deserialize, IterateParams, Store, ValueKey,
};
use utils::{
    config::{Config, ConfigKey},
    glob::GlobPattern,
};

#[derive(Default)]
pub struct ConfigManager {
    pub cfg_local: ArcSwap<BTreeMap<String, String>>,
    pub cfg_local_path: PathBuf,
    pub cfg_local_patterns: Arc<Patterns>,
    pub cfg_store: Store,
}

#[derive(Default)]
pub struct Patterns {
    patterns: Vec<Pattern>,
}

enum Pattern {
    Include(MatchType),
    Exclude(MatchType),
}

enum MatchType {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
    Matches(GlobPattern),
    All,
}

pub(crate) struct ExternalConfig {
    pub id: String,
    pub version: String,
    pub keys: Vec<ConfigKey>,
}

impl ConfigManager {
    pub async fn build_config(&self, prefix: &str) -> trc::Result<Config> {
        let mut config = Config {
            keys: self.cfg_local.load().as_ref().clone(),
            ..Default::default()
        };
        config.resolve_all_macros().await;
        self.extend_config(&mut config, prefix)
            .await
            .map(|_| config)
    }

    pub(crate) async fn extend_config(&self, config: &mut Config, prefix: &str) -> trc::Result<()> {
        for (key, value) in self.db_list(prefix, false).await? {
            config.keys.entry(key).or_insert(value);
        }

        Ok(())
    }

    pub async fn get(&self, key: impl AsRef<str>) -> trc::Result<Option<String>> {
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
    ) -> trc::Result<BTreeMap<String, String>> {
        let mut results = self.db_list(prefix, strip_prefix).await?;
        for (key, value) in self.cfg_local.load().iter() {
            if prefix.is_empty() || (!strip_prefix && key.starts_with(prefix)) {
                results.insert(key.clone(), value.clone());
            } else if let Some(key) = key.strip_prefix(prefix) {
                results.insert(key.to_string(), value.clone());
            }
        }

        Ok(results)
    }

    pub async fn group(
        &self,
        prefix: &str,
        suffix: &str,
    ) -> trc::Result<AHashMap<String, AHashMap<String, String>>> {
        let mut grouped = AHashMap::new();

        let mut list = self.list(prefix, true).await?;
        for key in list.keys() {
            if let Some(key) = key.strip_suffix(suffix) {
                grouped.insert(key.to_string(), AHashMap::new());
            }
        }

        for (name, entries) in &mut grouped {
            let prefix = format!("{name}.");
            for (key, value) in &mut list {
                if let Some(key) = key.strip_prefix(&prefix) {
                    entries.insert(key.to_string(), std::mem::take(value));
                }
            }
        }

        Ok(grouped)
    }

    async fn db_list(
        &self,
        prefix: &str,
        strip_prefix: bool,
    ) -> trc::Result<BTreeMap<String, String>> {
        let key = prefix.as_bytes();
        let from_key = ValueKey::from(ValueClass::Config(key.to_vec()));
        let to_key = ValueKey::from(ValueClass::Config(
            key.iter()
                .copied()
                .chain([u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX])
                .collect::<Vec<_>>(),
        ));
        let mut results = BTreeMap::new();
        let patterns = self.cfg_local_patterns.clone();
        self.cfg_store
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let mut key = std::str::from_utf8(key).map_err(|_| {
                        trc::Error::corrupted_key(key, value.into(), trc::location!())
                    })?;

                    if !patterns.is_local_key(key) {
                        if strip_prefix && !prefix.is_empty() {
                            key = key.strip_prefix(prefix).unwrap_or(key);
                        }

                        results.insert(key.to_string(), String::deserialize(value)?);
                    }

                    Ok(true)
                },
            )
            .await?;

        Ok(results)
    }

    pub async fn set<I, T>(&self, keys: I) -> trc::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<ConfigKey>,
    {
        let mut batch = BatchBuilder::new();
        let mut local_batch = Vec::new();

        for key in keys {
            let key = key.into();
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

    pub async fn clear(&self, key: impl AsRef<str>) -> trc::Result<()> {
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

    pub async fn clear_prefix(&self, key: impl AsRef<str>) -> trc::Result<()> {
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

    async fn update_local(&self, map: BTreeMap<String, String>) -> trc::Result<()> {
        let mut cfg_text = String::with_capacity(1024);
        for (key, value) in &map {
            cfg_text.push_str(key);
            cfg_text.push_str(" = ");
            if value == "true" || value == "false" || value.parse::<f64>().is_ok() {
                cfg_text.push_str(value);
            } else {
                let mut needs_escape = false;
                let mut has_lf = false;

                for ch in value.chars() {
                    match ch {
                        '"' | '\\' => {
                            needs_escape = true;
                            if has_lf {
                                break;
                            }
                        }
                        '\n' => {
                            has_lf = true;
                            if needs_escape {
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if has_lf || (value.len() > 50 && needs_escape) {
                    cfg_text.push_str("'''");
                    cfg_text.push_str(value);
                    cfg_text.push_str("'''");
                } else {
                    cfg_text.push('"');
                    if needs_escape {
                        for ch in value.chars() {
                            if ch == '\\' || ch == '"' {
                                cfg_text.push('\\');
                            }
                            cfg_text.push(ch);
                        }
                    } else {
                        cfg_text.push_str(value);
                    }
                    cfg_text.push('"');
                }
            }
            cfg_text.push('\n');
        }

        self.cfg_local.store(map.into());

        tokio::fs::write(&self.cfg_local_path, cfg_text)
            .await
            .map_err(|err| {
                trc::EventType::Config(trc::ConfigEvent::WriteError)
                    .reason(err)
                    .details("Failed to write local configuration")
                    .ctx(trc::Key::Path, self.cfg_local_path.display().to_string())
            })
    }

    pub async fn update_config_resource(&self, resource_id: &str) -> trc::Result<Option<String>> {
        let external = self
            .fetch_config_resource(resource_id)
            .await
            .map_err(|reason| {
                trc::EventType::Config(trc::ConfigEvent::FetchError)
                    .caused_by(trc::location!())
                    .details("Failed to fetch external configuration")
                    .ctx(trc::Key::Reason, reason)
            })?;

        if self
            .get(&external.id)
            .await?
            .map_or(true, |v| v != external.version)
        {
            self.set(external.keys).await?;

            trc::event!(
                Config(trc::ConfigEvent::ImportExternal),
                Version = external.version.clone(),
                Id = resource_id.to_string(),
            );

            Ok(Some(external.version))
        } else {
            trc::event!(
                Config(trc::ConfigEvent::AlreadyUpToDate),
                Version = external.version,
                Id = resource_id.to_string(),
            );

            Ok(None)
        }
    }

    pub(crate) async fn fetch_config_resource(
        &self,
        resource_id: &str,
    ) -> Result<ExternalConfig, String> {
        let config = String::from_utf8(self.fetch_resource(resource_id).await?)
            .map_err(|err| format!("Configuration file has invalid UTF-8: {err}"))?;
        let config = Config::new(config)
            .map_err(|err| format!("Failed to parse external configuration: {err}"))?;

        // Import configuration
        let mut external = ExternalConfig {
            id: String::new(),
            version: String::new(),
            keys: Vec::new(),
        };
        for (key, value) in config.keys {
            if key.starts_with("version.") {
                external.id.clone_from(&key);
                external.version.clone_from(&value);
                external.keys.push(ConfigKey::from((key, value)));
            } else if key.starts_with("queue.quota.")
                || key.starts_with("queue.throttle.")
                || key.starts_with("session.throttle.")
                || (key.starts_with("lookup.") && !key.starts_with("lookup.default."))
                || key.starts_with("sieve.trusted.scripts.")
            {
                external.keys.push(ConfigKey::from((key, value)));
            } else {
                trc::event!(
                    Config(trc::ConfigEvent::ExternalKeyIgnored),
                    Key = key,
                    Value = value,
                    Id = resource_id.to_string(),
                );
            }
        }

        if !external.version.is_empty() {
            Ok(external)
        } else {
            Err("External configuration file does not contain a version key".to_string())
        }
    }

    pub async fn get_services(&self) -> trc::Result<Vec<(String, u16, bool)>> {
        let mut result = Vec::new();

        for listener in self
            .group("server.listener.", ".protocol")
            .await
            .unwrap_or_default()
            .into_values()
        {
            let is_tls = listener
                .get("tls.implicit")
                .map_or(false, |tls| tls == "true");
            let protocol = listener
                .get("protocol")
                .map(|s| s.as_str())
                .unwrap_or_default();
            let port = listener
                .get("bind")
                .or_else(|| {
                    listener.iter().find_map(|(key, value)| {
                        if key.starts_with("bind.") {
                            Some(value)
                        } else {
                            None
                        }
                    })
                })
                .and_then(|s| s.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()))
                .unwrap_or_default();

            if port > 0 {
                result.push((protocol.to_string(), port, is_tls));
            }
        }

        // Sort by name, then tls and finally port
        result.sort_unstable_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.1.cmp(&b.1))
        });

        Ok(result)
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
                Pattern::Include(MatchType::StartsWith("directory.".to_string())),
                Pattern::Include(MatchType::StartsWith("tracer.".to_string())),
                Pattern::Exclude(MatchType::StartsWith("server.blocked-ip.".to_string())),
                Pattern::Exclude(MatchType::StartsWith("server.allowed-ip.".to_string())),
                Pattern::Include(MatchType::StartsWith("server.".to_string())),
                Pattern::Include(MatchType::StartsWith("certificate.".to_string())),
                Pattern::Include(MatchType::StartsWith(
                    "authentication.fallback-admin.".to_string(),
                )),
                Pattern::Exclude(MatchType::Equal("cluster.key".to_string())),
                Pattern::Include(MatchType::StartsWith("cluster.".to_string())),
                Pattern::Include(MatchType::Equal("storage.data".to_string())),
                Pattern::Include(MatchType::Equal("storage.blob".to_string())),
                Pattern::Include(MatchType::Equal("storage.lookup".to_string())),
                Pattern::Include(MatchType::Equal("storage.fts".to_string())),
                Pattern::Include(MatchType::Equal("storage.directory".to_string())),
                Pattern::Include(MatchType::Equal("lookup.default.hostname".to_string())),
                Pattern::Include(MatchType::Equal("enterprise.license-key".to_string())),
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
