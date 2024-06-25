/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use deadpool::{
    managed::{Manager, Pool},
    Runtime,
};
use std::{sync::Arc, time::Duration};
use store::{Store, Stores};
use utils::config::Config;

use ahash::AHashMap;

use crate::{
    backend::{
        imap::ImapDirectory, ldap::LdapDirectory, memory::MemoryDirectory, smtp::SmtpDirectory,
        sql::SqlDirectory,
    },
    Directories, Directory, DirectoryInner,
};

use super::cache::CachedDirectory;

impl Directories {
    pub async fn parse(config: &mut Config, stores: &Stores, data_store: Store) -> Self {
        let mut directories = AHashMap::new();

        for id in config
            .sub_keys("directory", ".type")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            // Parse directory
            let id = id.as_str();
            #[cfg(feature = "test_mode")]
            {
                if config
                    .property_or_default::<bool>(("directory", id, "disable"), "false")
                    .unwrap_or(false)
                {
                    tracing::debug!("Skipping disabled directory {id:?}.");
                    continue;
                }
            }
            let protocol = config.value_require(("directory", id, "type")).unwrap();
            let prefix = ("directory", id);
            let store = match protocol {
                "internal" => Some(DirectoryInner::Internal(
                    if let Some(store_id) = config.value_require(("directory", id, "store")) {
                        if let Some(data) = stores.stores.get(store_id) {
                            data.clone()
                        } else {
                            config.new_parse_error(
                                ("directory", id, "store"),
                                "Store does not exist",
                            );
                            continue;
                        }
                    } else {
                        continue;
                    },
                )),
                "ldap" => LdapDirectory::from_config(config, prefix, data_store.clone())
                    .map(DirectoryInner::Ldap),
                "sql" => SqlDirectory::from_config(config, prefix, stores, data_store.clone())
                    .map(DirectoryInner::Sql),
                "imap" => ImapDirectory::from_config(config, prefix).map(DirectoryInner::Imap),
                "smtp" => {
                    SmtpDirectory::from_config(config, prefix, false).map(DirectoryInner::Smtp)
                }
                "lmtp" => {
                    SmtpDirectory::from_config(config, prefix, true).map(DirectoryInner::Smtp)
                }
                "memory" => MemoryDirectory::from_config(config, prefix, data_store.clone())
                    .await
                    .map(DirectoryInner::Memory),
                unknown => {
                    let err = format!("Unknown directory type: {unknown:?}");
                    config.new_parse_error(("directory", id, "type"), err);
                    continue;
                }
            };

            // Build directory
            if let Some(store) = store {
                let directory = Arc::new(Directory {
                    store,
                    cache: CachedDirectory::try_from_config(config, ("directory", id)),
                });

                // Add directory
                directories.insert(id.to_string(), directory);
            }
        }

        Directories { directories }
    }
}

pub(crate) fn build_pool<M: Manager>(
    config: &mut Config,
    prefix: &str,
    manager: M,
) -> utils::config::Result<Pool<M>> {
    Pool::builder(manager)
        .runtime(Runtime::Tokio1)
        .max_size(
            config
                .property_or_default((prefix, "pool.max-connections"), "10")
                .unwrap_or(10),
        )
        .create_timeout(
            config
                .property_or_default::<Duration>((prefix, "pool.timeout.create"), "30s")
                .unwrap_or_else(|| Duration::from_secs(30))
                .into(),
        )
        .wait_timeout(config.property_or_default((prefix, "pool.timeout.wait"), "30s"))
        .recycle_timeout(config.property_or_default((prefix, "pool.timeout.recycle"), "30s"))
        .build()
        .map_err(|err| {
            format!(
                "Failed to build pool for {prefix:?}: {err}",
                prefix = prefix,
                err = err
            )
        })
}
