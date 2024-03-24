use std::sync::Arc;

use arc_swap::ArcSwap;
use directory::{Directories, Directory};
use store::{BlobBackend, BlobStore, FtsStore, LookupStore, Store, Stores};
use utils::config::Config;

use crate::{Core, Network};

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

impl Core {
    pub async fn parse(config: &mut Config, stores: Stores) -> Self {
        let mut data = config
            .value_require_("storage.data")
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
            .value_require_("storage.blob")
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
            .value_require_("storage.lookup")
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
            .value_require_("storage.fts")
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
        let directories = Directories::parse(config, &stores, data.clone()).await;
        let directory = config
            .value_require_("storage.directory")
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
            storage: Storage {
                data,
                blob,
                fts,
                lookup,
                lookups: stores.lookup_stores,
                directory,
                directories: directories.directories,
                purge_schedules: stores.purge_schedules,
            },
        }
    }

    pub fn into_shared(self) -> Arc<ArcSwap<Self>> {
        Arc::new(ArcSwap::from_pointee(self))
    }
}
