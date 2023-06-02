use bb8::{ManageConnection, Pool};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
    time::Duration,
};
use utils::config::{utils::AsKey, Config};

use ahash::{AHashMap, AHashSet};

use crate::{
    imap::ImapDirectory, ldap::LdapDirectory, memory::MemoryDirectory, smtp::SmtpDirectory,
    sql::SqlDirectory, DirectoryConfig, Lookup,
};

pub trait ConfigDirectory {
    fn parse_directory(&self) -> utils::config::Result<DirectoryConfig>;
    fn parse_lookup_list(&self, key: impl AsKey) -> utils::config::Result<AHashSet<String>>;
}

impl ConfigDirectory for Config {
    fn parse_directory(&self) -> utils::config::Result<DirectoryConfig> {
        let mut config = DirectoryConfig {
            directories: AHashMap::new(),
            lookups: AHashMap::new(),
        };
        for id in self.sub_keys("directory") {
            // Parse domains list
            let domains = self.parse_lookup_list(("directory", id, "lookup.domains"))?;

            // Parse directory
            let protocol = self.value_require(("directory", id, "protocol"))?;
            let directory = match protocol {
                "ldap" => LdapDirectory::from_config(self, ("directory", id), domains)?,
                "sql" => SqlDirectory::from_config(self, ("directory", id), domains)?,
                "imap" => ImapDirectory::from_config(self, ("directory", id), domains)?,
                "smtp" => SmtpDirectory::from_config(self, ("directory", id), domains, false)?,
                "lmtp" => SmtpDirectory::from_config(self, ("directory", id), domains, true)?,
                "memory" => MemoryDirectory::from_config(self, ("directory", id))?,
                unknown => {
                    return Err(format!("Unknown directory type: {unknown:?}"));
                }
            };

            // Parse lookups
            let is_remote = protocol != "memory";
            for lookup_id in self.sub_keys(("directory", id, "lookup")) {
                let lookup = if is_remote {
                    Lookup::Directory {
                        directory: directory.clone(),
                        query: self
                            .value_require(("directory", id, "lookup", lookup_id))?
                            .to_string(),
                    }
                } else {
                    Lookup::List {
                        list: self.parse_lookup_list(("directory", id, "lookup", lookup_id))?,
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

    fn parse_lookup_list(&self, key: impl AsKey) -> utils::config::Result<AHashSet<String>> {
        let mut list = AHashSet::new();
        for (_, value) in self.values(key.clone()) {
            if let Some(path) = value.strip_prefix("file://") {
                for line in BufReader::new(File::open(path).map_err(|err| {
                    format!(
                        "Failed to read file {path:?} for list {}: {err}",
                        key.as_key()
                    )
                })?)
                .lines()
                {
                    let line_ = line.map_err(|err| {
                        format!(
                            "Failed to read file {path:?} for list {}: {err}",
                            key.as_key()
                        )
                    })?;
                    let line = line_.trim();
                    if !line.is_empty() {
                        list.insert(line.to_string());
                    }
                }
            } else {
                list.insert(value.to_string());
            }
        }
        Ok(list)
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
