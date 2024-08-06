/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use arc_swap::ArcSwap;
use store::Stores;
use utils::config::{ipmask::IpAddrOrMask, utils::ParseValue, Config};

use crate::{
    config::{
        server::{tls::parse_certificates, Servers},
        telemetry::Telemetry,
    },
    listener::blocked::BLOCKED_IP_KEY,
    Core,
};

use super::config::{ConfigManager, Patterns};

pub struct ReloadResult {
    pub config: Config,
    pub new_core: Option<Core>,
    pub tracers: Option<Telemetry>,
}

impl Core {
    pub async fn reload_blocked_ips(&self) -> trc::Result<ReloadResult> {
        let mut ip_addresses = AHashSet::new();
        let mut config = self.storage.config.build_config(BLOCKED_IP_KEY).await?;

        for ip in config
            .set_values(BLOCKED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(_)) => {}
                Err(err) => {
                    config.new_parse_error(BLOCKED_IP_KEY, err);
                }
            }
        }

        *self.network.blocked_ips.ip_addresses.write() = ip_addresses;

        Ok(config.into())
    }

    pub async fn reload_certificates(&self) -> trc::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("certificate").await?;
        let mut certificates = self.tls.certificates.load().as_ref().clone();

        parse_certificates(&mut config, &mut certificates, &mut Default::default());

        self.tls.certificates.store(certificates.into());

        Ok(config.into())
    }

    pub async fn reload_lookups(&self) -> trc::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("certificate").await?;
        let mut stores = Stores::default();
        stores.parse_memory_stores(&mut config);

        let mut core = self.clone();
        for (id, store) in stores.lookup_stores {
            core.storage.lookups.insert(id, store);
        }

        Ok(ReloadResult {
            config,
            new_core: core.into(),
            tracers: None,
        })
    }

    pub async fn reload(&self) -> trc::Result<ReloadResult> {
        let mut config = self.storage.config.build_config("").await?;

        // Parse tracers
        let tracers = Telemetry::parse(&mut config);

        // Load stores
        let mut stores = Stores {
            stores: self.storage.stores.clone(),
            blob_stores: self.storage.blobs.clone(),
            fts_stores: self.storage.ftss.clone(),
            lookup_stores: self.storage.lookups.clone(),
            purge_schedules: Default::default(),
        };
        stores.parse_stores(&mut config).await;
        stores.parse_lookups(&mut config).await;
        if !config.errors.is_empty() {
            return Ok(config.into());
        }

        // Build manager
        let manager = ConfigManager {
            cfg_local: ArcSwap::from_pointee(self.storage.config.cfg_local.load().as_ref().clone()),
            cfg_local_path: self.storage.config.cfg_local_path.clone(),
            cfg_local_patterns: Patterns::parse(&mut config).into(),
            cfg_store: config
                .value("storage.data")
                .and_then(|id| stores.stores.get(id))
                .cloned()
                .unwrap_or_default(),
        };

        // Parse settings and build shared core
        let mut core = Core::parse(&mut config, stores, manager).await;
        if !config.errors.is_empty() {
            return Ok(config.into());
        }

        // Copy ACME certificates
        let mut certificates = core.tls.certificates.load().as_ref().clone();
        for (cert_id, cert) in self.tls.certificates.load().iter() {
            certificates
                .entry(cert_id.to_string())
                .or_insert(cert.clone());
        }
        core.tls.certificates.store(certificates.into());
        core.tls
            .self_signed_cert
            .clone_from(&self.tls.self_signed_cert);

        // Parser servers
        let mut servers = Servers::parse(&mut config);
        servers.parse_tcp_acceptors(&mut config, core.clone().into_shared());

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
