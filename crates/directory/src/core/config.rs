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

use deadpool::{
    managed::{Manager, Pool},
    Runtime,
};
use regex::Regex;
use std::{sync::Arc, time::Duration};
use store::Stores;
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use ahash::AHashMap;

use crate::{
    backend::{
        imap::ImapDirectory, ldap::LdapDirectory, memory::MemoryDirectory, smtp::SmtpDirectory,
        sql::SqlDirectory,
    },
    AddressMapping, Directories, Directory, DirectoryInner,
};

use super::cache::CachedDirectory;

pub trait ConfigDirectory {
    fn parse_directory(
        &self,
        stores: &Stores,
        id_store: Option<&str>,
    ) -> utils::config::Result<Directories>;
}

impl ConfigDirectory for Config {
    fn parse_directory(
        &self,
        stores: &Stores,
        id_store: Option<&str>,
    ) -> utils::config::Result<Directories> {
        let mut config = Directories {
            directories: AHashMap::new(),
        };
        let id_store = id_store.and_then(|id| stores.stores.get(id).cloned());

        for id in self.sub_keys("directory") {
            // Parse directory
            let protocol = self.value_require(("directory", id, "type"))?;
            let prefix = ("directory", id);
            let store = match protocol {
                "internal" => DirectoryInner::Internal(
                    stores
                        .stores
                        .get(self.value_require(("directory", id, "store"))?)
                        .cloned()
                        .ok_or_else(|| {
                            format!(
                                "Failed to find store {:?} for directory {:?}.",
                                self.value_require(("directory", id, "store")).unwrap(),
                                id
                            )
                        })?,
                ),
                "ldap" => DirectoryInner::Ldap(LdapDirectory::from_config(
                    self,
                    prefix,
                    id_store.clone(),
                )?),
                "sql" => DirectoryInner::Sql(SqlDirectory::from_config(
                    self,
                    prefix,
                    stores,
                    id_store.clone(),
                )?),
                "imap" => DirectoryInner::Imap(ImapDirectory::from_config(self, prefix)?),
                "smtp" => DirectoryInner::Smtp(SmtpDirectory::from_config(self, prefix, false)?),
                "lmtp" => DirectoryInner::Smtp(SmtpDirectory::from_config(self, prefix, true)?),
                "memory" => DirectoryInner::Memory(MemoryDirectory::from_config(
                    self,
                    prefix,
                    id_store.clone(),
                )?),
                unknown => {
                    return Err(format!("Unknown directory type: {unknown:?}"));
                }
            };

            config.directories.insert(
                id.to_string(),
                Arc::new(Directory {
                    store,
                    catch_all: AddressMapping::from_config(
                        self,
                        ("directory", id, "options.catch-all"),
                    )?,
                    subaddressing: AddressMapping::from_config(
                        self,
                        ("directory", id, "options.subaddressing"),
                    )?,
                    cache: CachedDirectory::try_from_config(self, ("directory", id))?,
                }),
            );
        }

        Ok(config)
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

pub(crate) fn build_pool<M: Manager>(
    config: &Config,
    prefix: &str,
    manager: M,
) -> utils::config::Result<Pool<M>> {
    Pool::builder(manager)
        .runtime(Runtime::Tokio1)
        .max_size(config.property_or_static((prefix, "pool.max-connections"), "10")?)
        .create_timeout(
            config
                .property_or_static::<Duration>((prefix, "pool.timeout.create"), "30s")?
                .into(),
        )
        .wait_timeout(config.property_or_static((prefix, "pool.timeout.wait"), "30s")?)
        .recycle_timeout(config.property_or_static((prefix, "pool.timeout.recycle"), "30s")?)
        .build()
        .map_err(|err| {
            format!(
                "Failed to build pool for {prefix:?}: {err}",
                prefix = prefix,
                err = err
            )
        })
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
