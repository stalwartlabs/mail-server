/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use arc_swap::ArcSwap;
use store::Stores;
use utils::config::Config;

use crate::{
    Core, Server,
    config::{
        server::{Listeners, tls::parse_certificates},
        telemetry::Telemetry,
    },
    listener::blocked::{BLOCKED_IP_KEY, BlockedIps},
};

use super::config::{ConfigManager, Patterns};

pub struct ReloadResult {
    pub config: Config,
    pub new_core: Option<Core>,
    pub tracers: Option<Telemetry>,
}

impl Server {
    pub async fn reload_blocked_ips(&self) -> trc::Result<ReloadResult> {
        let mut config = self
            .core
            .storage
            .config
            .build_config(BLOCKED_IP_KEY)
            .await?;
        *self.inner.data.blocked_ips.write() = BlockedIps::parse(&mut config).blocked_ip_addresses;

        Ok(config.into())
    }

    pub async fn reload_certificates(&self) -> trc::Result<ReloadResult> {
        let mut config = self.core.storage.config.build_config("certificate").await?;
        let mut certificates = self.inner.data.tls_certificates.load().as_ref().clone();

        parse_certificates(&mut config, &mut certificates, &mut Default::default());

        self.inner.data.tls_certificates.store(certificates.into());

        Ok(config.into())
    }

    pub async fn reload_lookups(&self) -> trc::Result<ReloadResult> {
        let mut config = self.core.storage.config.build_config("lookup").await?;
        let mut stores = Stores::default();
        stores.parse_static_stores(&mut config, true);

        let mut core = self.core.as_ref().clone();
        for (id, store) in stores.in_memory_stores {
            core.storage.lookups.insert(id, store);
        }

        Ok(ReloadResult {
            config,
            new_core: core.into(),
            tracers: None,
        })
    }

    pub async fn reload(&self) -> trc::Result<ReloadResult> {
        let mut config = self.core.storage.config.build_config("").await?;

        // Load stores
        let mut stores = Stores {
            stores: self.core.storage.stores.clone(),
            blob_stores: self.core.storage.blobs.clone(),
            fts_stores: self.core.storage.ftss.clone(),
            in_memory_stores: self.core.storage.lookups.clone(),
            pubsub_stores: Default::default(),
            purge_schedules: Default::default(),
        };
        stores.parse_stores(&mut config).await;
        stores.parse_in_memory(&mut config, true).await;

        // Parse tracers
        let tracers = Telemetry::parse(&mut config, &stores);

        if !config.errors.is_empty() {
            return Ok(config.into());
        }

        // Build manager
        let manager = ConfigManager {
            cfg_local: ArcSwap::from_pointee(
                self.core.storage.config.cfg_local.load().as_ref().clone(),
            ),
            cfg_local_path: self.core.storage.config.cfg_local_path.clone(),
            cfg_local_patterns: Patterns::parse(&mut config).into(),
            cfg_store: config
                .value("storage.data")
                .and_then(|id| stores.stores.get(id))
                .cloned()
                .unwrap_or_default(),
        };

        // Parse settings and build shared core
        let core = Box::pin(Core::parse(&mut config, stores, manager)).await;
        if !config.errors.is_empty() {
            return Ok(config.into());
        }

        // Update TLS certificates
        let mut new_certificates = AHashMap::new();
        parse_certificates(&mut config, &mut new_certificates, &mut Default::default());
        let mut current_certificates = self.inner.data.tls_certificates.load().as_ref().clone();
        for (cert_id, cert) in new_certificates {
            current_certificates.insert(cert_id, cert);
        }
        self.inner
            .data
            .tls_certificates
            .store(current_certificates.into());

        // Update blocked IPs
        *self.inner.data.blocked_ips.write() = BlockedIps::parse(&mut config).blocked_ip_addresses;

        // Parser servers
        let mut servers = Listeners::parse(&mut config);
        servers.parse_tcp_acceptors(&mut config, self.inner.clone());

        Ok(if config.errors.is_empty() {
            ReloadResult {
                config,
                new_core: core.into(),
                tracers: tracers.into(),
            }
        } else {
            config.into()
        })
    }
}

impl From<Config> for ReloadResult {
    fn from(config: Config) -> Self {
        Self {
            config,
            new_core: None,
            tracers: None,
        }
    }
}
