/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use bb8::{ManageConnection, Pool};
use regex::Regex;
use sieve::runtime::{tests::glob::GlobPattern, Variable};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
    time::Duration,
};
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use ahash::AHashMap;

use crate::{
    imap::ImapDirectory, ldap::LdapDirectory, memory::MemoryDirectory, smtp::SmtpDirectory,
    sql::SqlDirectory, AddressMapping, DirectoryConfig, DirectoryOptions, Lookup, LookupList,
    MatchType,
};

pub trait ConfigDirectory {
    fn parse_directory(&self) -> utils::config::Result<DirectoryConfig>;
    fn parse_lookup_list<K: AsKey, T: InsertLine>(
        &self,
        key: K,
        format: LookupFormat,
    ) -> utils::config::Result<T>;
}

impl ConfigDirectory for Config {
    fn parse_directory(&self) -> utils::config::Result<DirectoryConfig> {
        let mut config = DirectoryConfig {
            directories: AHashMap::new(),
            lookups: AHashMap::new(),
        };
        for id in self.sub_keys("directory") {
            // Parse directory
            let protocol = self.value_require(("directory", id, "type"))?;
            let prefix = ("directory", id);
            let directory = match protocol {
                "ldap" => LdapDirectory::from_config(self, prefix)?,
                "sql" => SqlDirectory::from_config(self, prefix)?,
                "imap" => ImapDirectory::from_config(self, prefix)?,
                "smtp" => SmtpDirectory::from_config(self, prefix, false)?,
                "lmtp" => SmtpDirectory::from_config(self, prefix, true)?,
                "memory" => MemoryDirectory::from_config(self, prefix)?,
                unknown => {
                    return Err(format!("Unknown directory type: {unknown:?}"));
                }
            };

            // Add queries/filters as lookups
            let is_directory = ["sql", "ldap"].contains(&protocol);
            if is_directory {
                let name = if protocol == "sql" { "query" } else { "filter" };
                for lookup_id in self.sub_keys(("directory", id, name)) {
                    config.lookups.insert(
                        format!("{id}/{lookup_id}"),
                        Arc::new(Lookup::Directory {
                            directory: directory.clone(),
                            query: self
                                .value_require(("directory", id, name, lookup_id))?
                                .to_string(),
                        }),
                    );
                }
            }

            // Parse lookups
            for lookup_id in self.sub_keys(("directory", id, "lookup")) {
                let lookup = if is_directory {
                    Lookup::Directory {
                        directory: directory.clone(),
                        query: self
                            .value_require(("directory", id, "lookup", lookup_id))?
                            .to_string(),
                    }
                } else {
                    let key = ("directory", id, "lookup", lookup_id).as_key();
                    match self.property::<LookupType>((&key, "type"))? {
                        Some(LookupType::Map) => Lookup::Map {
                            map: self.parse_lookup_list(
                                (&key, "values"),
                                LookupFormat {
                                    lookup_type: LookupType::Map,
                                    comment: self.value((&key, "comment")).map(|s| s.to_string()),
                                    separator: self
                                        .value((&key, "separator"))
                                        .map(|s| s.to_string()),
                                },
                            )?,
                        },
                        Some(lookup_type) => Lookup::List {
                            list: self.parse_lookup_list(
                                (&key, "values"),
                                LookupFormat {
                                    lookup_type,
                                    comment: self.value((&key, "comment")).map(|s| s.to_string()),
                                    separator: None,
                                },
                            )?,
                        },
                        None => Lookup::List {
                            list: self.parse_lookup_list(
                                key,
                                LookupFormat {
                                    lookup_type: LookupType::List,
                                    comment: None,
                                    separator: None,
                                },
                            )?,
                        },
                    }
                };

                config
                    .lookups
                    .insert(format!("{id}/{lookup_id}"), Arc::new(lookup));
            }

            config.directories.insert(id.to_string(), directory);
        }

        Ok(config)
    }

    fn parse_lookup_list<K: AsKey, T: InsertLine>(
        &self,
        key: K,
        format: LookupFormat,
    ) -> utils::config::Result<T> {
        let mut list = T::default();
        let mut last_failed = false;
        for (_, mut value) in self.values(key.clone()) {
            if let Some(new_value) = value.strip_prefix("fallback+") {
                if last_failed {
                    value = new_value;
                } else {
                    continue;
                }
            }
            last_failed = false;

            if value.starts_with("https://") || value.starts_with("http://") {
                match tokio::task::block_in_place(|| {
                    reqwest::blocking::get(value).and_then(|r| {
                        if r.status().is_success() {
                            r.bytes().map(Ok)
                        } else {
                            Ok(Err(r))
                        }
                    })
                }) {
                    Ok(Ok(bytes)) => {
                        match list.insert_lines(&*bytes, &format, value.ends_with(".gz")) {
                            Ok(_) => continue,
                            Err(err) => {
                                tracing::warn!(
                                    "Failed to read list {key:?} from {value:?}: {err}",
                                    key = key.as_key(),
                                    value = value,
                                    err = err
                                );
                            }
                        }
                    }
                    Ok(Err(response)) => {
                        tracing::warn!(
                            "Failed to fetch list {key:?} from {value:?}: Status {status}",
                            key = key.as_key(),
                            value = value,
                            status = response.status()
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to fetch list {key:?} from {value:?}: {err}",
                            key = key.as_key(),
                            value = value,
                            err = err
                        );
                    }
                }
                last_failed = true;
            } else if let Some(path) = value.strip_prefix("file://") {
                list.insert_lines(
                    File::open(path).map_err(|err| {
                        format!(
                            "Failed to read file {path:?} for list {}: {err}",
                            key.as_key()
                        )
                    })?,
                    &format,
                    value.ends_with(".gz"),
                )
                .map_err(|err| {
                    format!(
                        "Failed to read file {path:?} for list {}: {err}",
                        key.as_key()
                    )
                })?;
            } else {
                list.insert(value.to_string(), &format);
            }
        }
        Ok(list)
    }
}

pub trait InsertLine: Default {
    fn insert(&mut self, entry: String, format: &LookupFormat);
    fn insert_lines<R: Sized + std::io::Read>(
        &mut self,
        reader: R,
        format: &LookupFormat,
        decompress: bool,
    ) -> Result<(), std::io::Error> {
        let reader: Box<dyn std::io::Read> = if decompress {
            Box::new(flate2::read::GzDecoder::new(reader))
        } else {
            Box::new(reader)
        };

        for line in BufReader::new(reader).lines() {
            let line_ = line?;
            let line = line_.trim();
            if !line.is_empty()
                && format
                    .comment
                    .as_ref()
                    .map_or(true, |c| !line.starts_with(c))
            {
                self.insert(line.to_string(), format);
            }
        }
        Ok(())
    }
}

impl InsertLine for LookupList {
    fn insert(&mut self, entry: String, format: &LookupFormat) {
        match format.lookup_type {
            LookupType::List => {
                self.set.insert(entry);
            }
            LookupType::Glob => {
                let n_wildcards = entry
                    .as_bytes()
                    .iter()
                    .filter(|&&ch| ch == b'*' || ch == b'?')
                    .count();
                if n_wildcards > 0 {
                    if n_wildcards == 1 {
                        if let Some(s) = entry.strip_prefix('*') {
                            if !s.is_empty() {
                                self.matches.push(MatchType::EndsWith(s.to_string()));
                            }
                            return;
                        } else if let Some(s) = entry.strip_suffix('*') {
                            if !s.is_empty() {
                                self.matches.push(MatchType::StartsWith(s.to_string()));
                            }
                            return;
                        }
                    }
                    self.matches
                        .push(MatchType::Glob(GlobPattern::compile(&entry, false)));
                } else {
                    self.set.insert(entry);
                }
            }
            LookupType::Regex => match regex::Regex::new(&entry) {
                Ok(regex) => {
                    self.matches.push(MatchType::Regex(regex));
                }
                Err(err) => {
                    tracing::warn!("Invalid regular expression {:?}: {}", entry, err);
                }
            },
            LookupType::Map => unreachable!(),
        }
    }
}

impl InsertLine for AHashMap<String, Variable> {
    fn insert(&mut self, entry: String, format: &LookupFormat) {
        let (key, value) = entry
            .split_once(format.separator.as_deref().unwrap_or(" "))
            .unwrap_or((entry.as_str(), ""));
        let key = key.trim();
        if key.is_empty() {
            return;
        } else if value.is_empty() {
            self.insert(key.to_string(), Variable::default());
            return;
        }
        let mut has_digit = false;
        let mut has_dots = false;
        let mut has_other = false;

        for (pos, ch) in value.bytes().enumerate() {
            if ch.is_ascii_digit() {
                has_digit = true;
            } else if ch == b'.' {
                has_dots = true;
            } else if pos > 0 || ch != b'-' {
                has_other = true;
            }
        }

        let value = if has_other || !has_digit {
            Variable::String(value.to_string().into())
        } else if has_dots {
            value
                .parse()
                .map(Variable::Float)
                .unwrap_or_else(|_| Variable::String(value.to_string().into()))
        } else {
            value
                .parse()
                .map(Variable::Integer)
                .unwrap_or_else(|_| Variable::String(value.to_string().into()))
        };

        self.insert(key.to_string(), value);
    }
}

impl DirectoryOptions {
    pub fn from_config(config: &Config, key: impl AsKey) -> utils::config::Result<Self> {
        let key = key.as_key();
        Ok(DirectoryOptions {
            catch_all: AddressMapping::from_config(config, (&key, "options.catch-all"))?,
            subaddressing: AddressMapping::from_config(config, (&key, "options.subaddressing"))?,
            superuser_group: config
                .value("options.superuser-group")
                .unwrap_or("superusers")
                .to_string(),
        })
    }
}

impl AddressMapping {
    pub fn from_config(config: &Config, key: impl AsKey) -> utils::config::Result<Self> {
        let key = key.as_key();
        if let Some(value) = config.value(key.as_str()) {
            match value {
                "true" => Ok(AddressMapping::Enable),
                "false" => Ok(AddressMapping::Disable),
                _ => Err(format!(
                    "Invalid value for address mapping {key:?}: {value:?}",
                )),
            }
        } else if let Some(regex) = config.value((key.as_str(), "map")) {
            Ok(AddressMapping::Custom {
                regex: Regex::new(regex).map_err(|err| {
                    format!(
                        "Failed to compile regular expression {:?} for key {:?}: {}.",
                        regex,
                        (&key, "map").as_key(),
                        err
                    )
                })?,
                mapping: config.property_require((key.as_str(), "to"))?,
            })
        } else {
            Ok(AddressMapping::Disable)
        }
    }
}

pub(crate) fn build_pool<M: ManageConnection>(
    config: &Config,
    prefix: &str,
    manager: M,
) -> utils::config::Result<Pool<M>> {
    Ok(Pool::builder()
        .min_idle(
            config
                .property((prefix, "pool.min-connections"))?
                .and_then(|v| if v > 0 { Some(v) } else { None }),
        )
        .max_size(config.property_or_static((prefix, "pool.max-connections"), "10")?)
        .max_lifetime(
            config
                .property_or_static::<Duration>((prefix, "pool.max-lifetime"), "30m")?
                .into(),
        )
        .idle_timeout(
            config
                .property_or_static::<Duration>((prefix, "pool.idle-timeout"), "10m")?
                .into(),
        )
        .connection_timeout(config.property_or_static((prefix, "pool.connect-timeout"), "30s")?)
        .test_on_check_out(true)
        .build_unchecked(manager))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    List,
    Glob,
    Regex,
    Map,
}

#[derive(Debug, Clone)]
pub struct LookupFormat {
    pub lookup_type: LookupType,
    pub comment: Option<String>,
    pub separator: Option<String>,
}

impl Default for LookupFormat {
    fn default() -> Self {
        Self {
            lookup_type: LookupType::Glob,
            comment: Default::default(),
            separator: Default::default(),
        }
    }
}

impl ParseValue for LookupType {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
        match value {
            "list" => Ok(LookupType::List),
            "glob" => Ok(LookupType::Glob),
            "regex" => Ok(LookupType::Regex),
            "map" => Ok(LookupType::Map),
            _ => Err(format!(
                "Invalid value for lookup type {key:?}: {value:?}",
                key = key.as_key(),
                value = value
            )),
        }
    }
}
