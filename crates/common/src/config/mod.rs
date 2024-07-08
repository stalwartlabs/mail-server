/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use arc_swap::ArcSwap;
use directory::{Directories, Directory};
use store::{BlobBackend, BlobStore, FtsStore, LookupStore, Store, Stores};
use utils::config::Config;

use crate::{
    expr::*, listener::tls::TlsManager, manager::config::ConfigManager, webhooks::Webhooks, Core,
    Network,
};

#[cfg(feature = "enterprise")]
use crate::Enterprise;
#[cfg(feature = "enterprise")]
use jmap_proto::types::collection::Collection;
#[cfg(feature = "enterprise")]
use se_licensing::license::LicenseValidator;

use self::{
    imap::ImapConfig, jmap::settings::JmapConfig, scripts::Scripting, smtp::SmtpConfig,
    storage::Storage,
};

pub mod imap;
pub mod jmap;
pub mod network;
pub mod scripts;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod tracers;

pub(crate) const CONNECTION_VARS: &[u32; 7] = &[
    V_LISTENER,
    V_REMOTE_IP,
    V_REMOTE_PORT,
    V_LOCAL_IP,
    V_LOCAL_PORT,
    V_PROTOCOL,
    V_TLS,
];

impl Core {
    pub async fn parse(config: &mut Config, stores: Stores, config_manager: ConfigManager) -> Self {
        let mut data = config
            .value_require("storage.data")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error("storage.data", format!("Data store {id:?} not found"));
                    None
                }
            })
            .unwrap_or_default();
        let mut blob = config
            .value_require("storage.blob")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.blob_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error("storage.blob", format!("Blob store {id:?} not found"));
                    None
                }
            })
            .unwrap_or_default();
        let mut lookup = config
            .value_require("storage.lookup")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.lookup_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.lookup",
                        format!("Lookup store {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_default();
        let mut fts = config
            .value_require("storage.fts")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(store) = stores.fts_stores.get(&id) {
                    store.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.fts",
                        format!("Full-text store {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_default();
        let mut directories = Directories::parse(config, &stores, data.clone()).await;
        let directory = config
            .value_require("storage.directory")
            .map(|id| id.to_string())
            .and_then(|id| {
                if let Some(directory) = directories.directories.get(&id) {
                    directory.clone().into()
                } else {
                    config.new_parse_error(
                        "storage.directory",
                        format!("Directory {id:?} not found"),
                    );
                    None
                }
            })
            .unwrap_or_else(|| Arc::new(Directory::default()));
        directories
            .directories
            .insert("*".to_string(), directory.clone());

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        let enterprise = match config.value("enterprise.license-key").map(|key| {
            LicenseValidator::new().try_parse(key).and_then(|key| {
                key.into_validated_key(config.value("lookup.default.hostname").unwrap_or_default())
            })
        }) {
            Some(Ok(license)) => {
                match data
                    .get_bitmap(store::BitmapKey::document_ids(
                        u32::MAX,
                        Collection::Principal,
                    ))
                    .await
                {
                    Ok(Some(bitmap)) if bitmap.len() > license.accounts as u64 => {
                        config.new_build_warning(
                            "enterprise.license-key",
                            format!(
                                "License key is valid but only allows {} accounts, found {}.",
                                license.accounts,
                                bitmap.len()
                            ),
                        );
                        None
                    }
                    Err(e) => {
                        if !matches!(data, Store::None) {
                            config.new_build_error("enterprise.license-key", e.to_string());
                        }
                        None
                    }
                    _ => Some(Enterprise {
                        license,
                        undelete_period: config
                            .property_or_default::<Option<std::time::Duration>>(
                                "enterprise.undelete-period",
                                "false",
                            )
                            .unwrap_or_default(),
                    }),
                }
            }
            Some(Err(e)) => {
                config.new_build_warning("enterprise.license-key", e.to_string());
                None
            }
            None => None,
        };
        // SPDX-SnippetEnd

        // If any of the stores are missing, disable all stores to avoid data loss
        if matches!(data, Store::None)
            || matches!(&blob.backend, BlobBackend::Store(Store::None))
            || matches!(lookup, LookupStore::Store(Store::None))
            || matches!(fts, FtsStore::Store(Store::None))
        {
            data = Store::default();
            blob = BlobStore::default();
            lookup = LookupStore::default();
            fts = FtsStore::default();
            config.new_build_error(
                "storage.*",
                "One or more stores are missing, disabling all stores",
            )
        }

        Self {
            sieve: Scripting::parse(config, &stores).await,
            network: Network::parse(config),
            smtp: SmtpConfig::parse(config).await,
            jmap: JmapConfig::parse(config),
            imap: ImapConfig::parse(config),
            tls: TlsManager::parse(config),
            web_hooks: Webhooks::parse(config),
            storage: Storage {
                data,
                blob,
                fts,
                lookup,
                directory,
                directories: directories.directories,
                purge_schedules: stores.purge_schedules,
                config: config_manager,
                stores: stores.stores,
                lookups: stores.lookup_stores,
                blobs: stores.blob_stores,
                ftss: stores.fts_stores,
            },
            #[cfg(feature = "enterprise")]
            enterprise,
        }
    }

    pub fn into_shared(self) -> Arc<ArcSwap<Self>> {
        Arc::new(ArcSwap::from_pointee(self))
    }
}
