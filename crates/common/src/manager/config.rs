/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::{BTreeMap, btree_map::Entry},
    path::PathBuf,
    sync::Arc,
};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use store::{
    Deserialize, IterateParams, Store, ValueKey,
    write::{BatchBuilder, ValueClass},
};
use trc::AddContext;
use utils::{
    Semver,
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

#[derive(Debug)]
enum Pattern {
    Include(MatchType),
    Exclude(MatchType),
}

#[derive(Debug, Clone)]
pub enum MatchType {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
    Matches(GlobPattern),
    All,
}

pub(crate) struct ExternalSpamRules {
    pub version: Semver,
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

    pub async fn db_list(
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
            .await
            .caused_by(trc::location!())?;

        Ok(results)
    }

    pub async fn set<I, T>(&self, keys: I, overwrite: bool) -> trc::Result<()>
    where
        I: IntoIterator<Item = T>,
        T: Into<ConfigKey>,
    {
        let mut batch = BatchBuilder::new();
        let mut local_batch = Vec::new();

        for key in keys {
            let key = key.into();

            if overwrite || self.get(&key.key).await?.is_none() || key.key.starts_with("version.") {
                if self.cfg_local_patterns.is_local_key(&key.key) {
                    local_batch.push(key);
                } else {
                    batch.set(ValueClass::Config(key.key.into_bytes()), key.value);
                }
            }
        }

        if !batch.is_empty() {
            self.cfg_store.write(batch.build_all()).await?;
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
            self.cfg_store.write(batch.build_all()).await.map(|_| ())
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

    pub async fn update_spam_rules(
        &self,
        force_update: bool,
        overwrite: bool,
    ) -> trc::Result<Option<Semver>> {
        let current_version = self
            .get("version.spam-filter")
            .await?
            .and_then(|v| Semver::try_from(v.as_str()).ok());
        let is_update = current_version.is_some();

        let mut external = self.fetch_spam_rules().await.map_err(|reason| {
            trc::EventType::Config(trc::ConfigEvent::FetchError)
                .caused_by(trc::location!())
                .details("Failed to update spam filter rules")
                .ctx(trc::Key::Reason, reason)
        })?;

        if current_version.is_none_or(|v| external.version > v || force_update) {
            if is_update {
                // Delete previous STWT_* rules
                let mut rule_settings = AHashMap::new();
                for prefix in [
                    "spam-filter.rule.stwt_",
                    "spam-filter.dnsbl.server.stwt_",
                    "http-lookup.stwt_",
                ] {
                    for (key, value) in self.list(prefix, false).await? {
                        if key.ends_with(".enable") {
                            rule_settings.insert(key, value);
                        }
                    }

                    self.clear_prefix(prefix).await?;
                }

                // Update keys
                if !rule_settings.is_empty() {
                    for key in &mut external.keys {
                        if let Some(value) = rule_settings.remove(&key.key) {
                            key.value = value;
                        }
                    }
                }

                if !overwrite {
                    // Do not overwrite ASN or LLM settings
                    external.keys.retain(|key| {
                        !key.key.starts_with("spam-filter.llm.") && !key.key.starts_with("asn.")
                    });
                }
            }

            self.set(external.keys, overwrite).await?;

            trc::event!(
                Config(trc::ConfigEvent::ImportExternal),
                Version = external.version.to_string(),
                Id = "spam-filter",
            );

            Ok(Some(external.version))
        } else {
            trc::event!(
                Config(trc::ConfigEvent::AlreadyUpToDate),
                Version = external.version.to_string(),
                Id = "spam-filter",
            );

            Ok(None)
        }
    }

    pub(crate) async fn fetch_spam_rules(&self) -> Result<ExternalSpamRules, String> {
        let config = String::from_utf8(self.fetch_resource("spam-filter").await?)
            .map_err(|err| format!("Configuration file has invalid UTF-8: {err}"))?;
        let config = Config::new(config)
            .map_err(|err| format!("Failed to parse external configuration: {err}"))?;

        // Import configuration
        let mut external = ExternalSpamRules {
            version: Semver::default(),
            keys: Vec::new(),
        };
        let mut required_semver = Semver::default();
        let server_semver: Semver = env!("CARGO_PKG_VERSION").try_into().unwrap();
        for (key, value) in config.keys {
            if key == "version.spam-filter" {
                external.version = value.as_str().try_into().unwrap_or_default();
                external.keys.push(ConfigKey::from((key, value)));
            } else if key == "version.server" {
                required_semver = value.as_str().try_into().unwrap_or_default();
            } else if key.starts_with("spam-filter.")
                || key.starts_with("http-lookup.")
                || key.starts_with("lookup.")
                || key.starts_with("asn.")
            {
                external.keys.push(ConfigKey::from((key, value)));
            }
        }

        if !required_semver.is_valid() {
            Err("External spam filter rules do not contain a valid server version".to_string())
        } else if required_semver > server_semver {
            Err(format!(
                "External spam filter rules require server version {required_semver}, but this is version {server_semver}",
            ))
        } else if external.version.is_valid() {
            Ok(external)
        } else {
            Err("External spam filter rules do not contain a version key".to_string())
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
                .is_some_and(|tls| tls == "true");
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
            let match_type = MatchType::parse(&value);

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
                Pattern::Include(MatchType::StartsWith("config.local-keys.".to_string())),
                Pattern::Include(MatchType::StartsWith(
                    "authentication.fallback-admin.".to_string(),
                )),
                Pattern::Include(MatchType::StartsWith("cluster.".to_string())),
                Pattern::Include(MatchType::Equal("storage.data".to_string())),
                Pattern::Include(MatchType::Equal("storage.blob".to_string())),
                Pattern::Include(MatchType::Equal("storage.lookup".to_string())),
                Pattern::Include(MatchType::Equal("storage.fts".to_string())),
                Pattern::Include(MatchType::Equal("storage.directory".to_string())),
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
    pub fn parse(value: &str) -> Self {
        if value == "*" {
            MatchType::All
        } else if let Some(value) = value.strip_suffix('*') {
            MatchType::StartsWith(value.to_string())
        } else if let Some(value) = value.strip_prefix('*') {
            MatchType::EndsWith(value.to_string())
        } else if value.contains('*') {
            MatchType::Matches(GlobPattern::compile(value, false))
        } else {
            MatchType::Equal(value.to_string())
        }
    }

    pub fn matches(&self, value: &str) -> bool {
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
