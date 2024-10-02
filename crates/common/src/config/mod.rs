/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use arc_swap::ArcSwap;
use directory::{Directories, Directory};
use ring::signature::{EcdsaKeyPair, RsaKeyPair};
use store::{BlobBackend, BlobStore, FtsStore, LookupStore, Store, Stores};
use telemetry::Metrics;
use utils::config::Config;

use crate::{
    auth::oauth::config::OAuthConfig, expr::*, listener::tls::AcmeProviders,
    manager::config::ConfigManager, Core, Network, Security,
};

use self::{
    imap::ImapConfig, jmap::settings::JmapConfig, scripts::Scripting, smtp::SmtpConfig,
    storage::Storage,
};

pub mod imap;
pub mod inner;
pub mod jmap;
pub mod network;
pub mod scripts;
pub mod server;
pub mod smtp;
pub mod storage;
pub mod telemetry;

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
    pub async fn parse(
        config: &mut Config,
        mut stores: Stores,
        config_manager: ConfigManager,
    ) -> Self {
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

        #[cfg(not(feature = "enterprise"))]
        let is_enterprise = false;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let enterprise = crate::enterprise::Enterprise::parse(config, &stores, &data).await;

        #[cfg(feature = "enterprise")]
        let is_enterprise = enterprise.is_some();

        #[cfg(feature = "enterprise")]
        if is_enterprise {
            if data.is_enterprise_store() {
                config
                    .new_build_error("storage.data", "SQL read replicas is an Enterprise feature");
                data = Store::None;
            }
            stores.disable_enterprise_only();
        }
        // SPDX-SnippetEnd

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
        let mut directories =
            Directories::parse(config, &stores, data.clone(), is_enterprise).await;
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
            #[cfg(feature = "enterprise")]
            enterprise,
            sieve: Scripting::parse(config, &stores).await,
            network: Network::parse(config),
            smtp: SmtpConfig::parse(config).await,
            jmap: JmapConfig::parse(config),
            imap: ImapConfig::parse(config),
            oauth: OAuthConfig::parse(config),
            acme: AcmeProviders::parse(config),
            metrics: Metrics::parse(config),
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
        }
    }

    pub fn into_shared(self) -> ArcSwap<Self> {
        ArcSwap::from_pointee(self)
    }
}

pub fn build_rsa_keypair(pem: &str) -> Result<RsaKeyPair, String> {
    match rustls_pemfile::read_one(&mut pem.as_bytes()) {
        Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => {
            RsaKeyPair::from_der(key.secret_pkcs1_der())
                .map_err(|err| format!("Failed to parse PKCS1 RSA key: {err}"))
        }
        Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => {
            RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
                .map_err(|err| format!("Failed to parse PKCS8 RSA key: {err}"))
        }
        Err(err) => Err(format!("Failed to read PEM: {err}")),
        Ok(Some(key)) => Err(format!("Unsupported key type: {key:?}")),
        Ok(None) => Err("No RSA key found in PEM".to_string()),
    }
}

pub fn build_ecdsa_pem(
    alg: &'static ring::signature::EcdsaSigningAlgorithm,
    pem: &str,
) -> Result<EcdsaKeyPair, String> {
    match rustls_pemfile::read_one(&mut pem.as_bytes()) {
        Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => EcdsaKeyPair::from_pkcs8(
            alg,
            key.secret_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|err| format!("Failed to parse PKCS8 ECDSA key: {err}")),
        Err(err) => Err(format!("Failed to read PEM: {err}")),
        Ok(Some(key)) => Err(format!("Unsupported key type: {key:?}")),
        Ok(None) => Err("No ECDSA key found in PEM".to_string()),
    }
}
