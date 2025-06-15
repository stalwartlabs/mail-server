/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Debug, net::IpAddr};

use ahash::AHashSet;
use utils::{
    config::{
        Config, ConfigKey, Rate,
        ipmask::{IpAddrMask, IpAddrOrMask},
        utils::ParseValue,
    },
    glob::GlobPattern,
};

use crate::{
    KV_RATE_LIMIT_AUTH, KV_RATE_LIMIT_LOITER, KV_RATE_LIMIT_RCPT, KV_RATE_LIMIT_SCAN, Server,
    ip_to_bytes, ipc::BroadcastEvent, manager::config::MatchType,
};

#[derive(Debug, Clone)]
pub struct Security {
    blocked_ip_networks: Vec<IpAddrMask>,
    has_blocked_networks: bool,

    allowed_ip_addresses: AHashSet<IpAddr>,
    allowed_ip_networks: Vec<IpAddrMask>,
    has_allowed_networks: bool,

    http_banned_paths: Vec<MatchType>,
    scanner_fail_rate: Option<Rate>,

    auth_fail_rate: Option<Rate>,
    rcpt_fail_rate: Option<Rate>,
    loiter_fail_rate: Option<Rate>,
}

pub const BLOCKED_IP_KEY: &str = "server.blocked-ip";
pub const BLOCKED_IP_PREFIX: &str = "server.blocked-ip.";
pub const ALLOWED_IP_KEY: &str = "server.allowed-ip";
pub const ALLOWED_IP_PREFIX: &str = "server.allowed-ip.";

pub struct BlockedIps {
    pub blocked_ip_addresses: AHashSet<IpAddr>,
    pub blocked_ip_networks: Vec<IpAddrMask>,
}

impl Security {
    pub fn parse(config: &mut Config) -> Self {
        let mut allowed_ip_addresses = AHashSet::new();
        let mut allowed_ip_networks = Vec::new();

        for ip in config
            .set_values(ALLOWED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    allowed_ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(ip)) => {
                    allowed_ip_networks.push(ip);
                }
                Err(err) => {
                    config.new_parse_error(ALLOWED_IP_KEY, err);
                }
            }
        }

        #[cfg(not(feature = "test_mode"))]
        {
            // Add loopback addresses
            allowed_ip_addresses.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            allowed_ip_addresses.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        }

        let blocked = BlockedIps::parse(config);

        // Parse blocked HTTP paths
        let mut http_banned_paths = config
            .values("server.auto-ban.scan.paths")
            .filter_map(|(_, v)| {
                let v = v.trim();
                if !v.is_empty() {
                    MatchType::parse(v).into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if http_banned_paths.is_empty() {
            for pattern in [
                "*.php*",
                "*.cgi*",
                "*.asp*",
                "*/wp-*",
                "*/php*",
                "*/cgi-bin*",
                "*xmlrpc*",
                "*../*",
                "*/..*",
                "*joomla*",
                "*wordpress*",
                "*drupal*",
            ]
            .iter()
            {
                http_banned_paths.push(MatchType::Matches(GlobPattern::compile(pattern, true)));
            }
        }

        Security {
            has_blocked_networks: !blocked.blocked_ip_networks.is_empty(),
            blocked_ip_networks: blocked.blocked_ip_networks,
            has_allowed_networks: !allowed_ip_networks.is_empty(),
            allowed_ip_addresses,
            allowed_ip_networks,
            auth_fail_rate: config
                .property_or_default::<Option<Rate>>("server.auto-ban.auth.rate", "100/1d")
                .unwrap_or_default(),
            rcpt_fail_rate: config
                .property_or_default::<Option<Rate>>("server.auto-ban.abuse.rate", "35/1d")
                .unwrap_or_default(),
            loiter_fail_rate: config
                .property_or_default::<Option<Rate>>("server.auto-ban.loiter.rate", "150/1d")
                .unwrap_or_default(),
            http_banned_paths,
            scanner_fail_rate: config
                .property_or_default::<Option<Rate>>("server.auto-ban.scan.rate", "30/1d")
                .unwrap_or_default(),
        }
    }
}

impl Server {
    pub async fn is_rcpt_fail2banned(&self, ip: IpAddr, rcpt: &str) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.rcpt_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || (self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_RCPT, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none()
                    && self
                        .in_memory_store()
                        .is_rate_allowed(KV_RATE_LIMIT_RCPT, rcpt.as_bytes(), rate, false)
                        .await?
                        .is_none());

            if !is_allowed {
                return self.block_ip(ip).await.map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_scanner_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.scanner_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_SCAN, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self.block_ip(ip).await.map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_http_banned_path(&self, path: &str, ip: IpAddr) -> trc::Result<bool> {
        let paths = &self.core.network.security.http_banned_paths;

        if !paths.is_empty() && paths.iter().any(|p| p.matches(path)) && !self.is_ip_allowed(&ip) {
            self.block_ip(ip).await.map(|_| true)
        } else {
            Ok(false)
        }
    }

    pub async fn is_loiter_fail2banned(&self, ip: IpAddr) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.loiter_fail_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_LOITER, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none();

            if !is_allowed {
                return self.block_ip(ip).await.map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn is_auth_fail2banned(&self, ip: IpAddr, login: Option<&str>) -> trc::Result<bool> {
        if let Some(rate) = &self.core.network.security.auth_fail_rate {
            let login = login.unwrap_or_default();
            let is_allowed = self.is_ip_allowed(&ip)
                || (self
                    .in_memory_store()
                    .is_rate_allowed(KV_RATE_LIMIT_AUTH, &ip_to_bytes(&ip), rate, false)
                    .await?
                    .is_none()
                    && (login.is_empty()
                        || self
                            .in_memory_store()
                            .is_rate_allowed(KV_RATE_LIMIT_AUTH, login.as_bytes(), rate, false)
                            .await?
                            .is_none()));
            if !is_allowed {
                return self.block_ip(ip).await.map(|_| true);
            }
        }

        Ok(false)
    }

    pub async fn block_ip(&self, ip: IpAddr) -> trc::Result<()> {
        // Add IP to blocked list
        self.inner.data.blocked_ips.write().insert(ip);

        // Write blocked IP to config
        self.core
            .storage
            .config
            .set(
                [ConfigKey {
                    key: format!("{}.{}", BLOCKED_IP_KEY, ip),
                    value: String::new(),
                }],
                true,
            )
            .await?;

        // Increment version
        self.cluster_broadcast(BroadcastEvent::ReloadBlockedIps)
            .await;

        Ok(())
    }

    pub fn has_auth_fail2ban(&self) -> bool {
        self.core.network.security.auth_fail_rate.is_some()
    }

    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.inner.data.blocked_ips.read().contains(ip)
            || (self.core.network.security.has_blocked_networks
                && self
                    .core
                    .network
                    .security
                    .blocked_ip_networks
                    .iter()
                    .any(|network| network.matches(ip)))
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.core.network.security.allowed_ip_addresses.contains(ip)
            || (self.core.network.security.has_allowed_networks
                && self
                    .core
                    .network
                    .security
                    .allowed_ip_networks
                    .iter()
                    .any(|network| network.matches(ip)))
    }
}

impl BlockedIps {
    pub fn parse(config: &mut Config) -> Self {
        let mut blocked_ip_addresses = AHashSet::new();
        let mut blocked_ip_networks = Vec::new();

        for ip in config
            .set_values(BLOCKED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    blocked_ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(ip)) => {
                    blocked_ip_networks.push(ip);
                }
                Err(err) => {
                    config.new_parse_error(BLOCKED_IP_KEY, err);
                }
            }
        }

        Self {
            blocked_ip_addresses,
            blocked_ip_networks,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Security {
    fn default() -> Self {
        // Add IPv4 and IPv6 loopback addresses
        Self {
            #[cfg(not(feature = "test_mode"))]
            allowed_ip_addresses: AHashSet::from_iter([
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ]),
            #[cfg(feature = "test_mode")]
            allowed_ip_addresses: Default::default(),
            allowed_ip_networks: Default::default(),
            has_allowed_networks: Default::default(),
            blocked_ip_networks: Default::default(),
            has_blocked_networks: Default::default(),
            auth_fail_rate: Default::default(),
            rcpt_fail_rate: Default::default(),
            loiter_fail_rate: Default::default(),
            scanner_fail_rate: Default::default(),
            http_banned_paths: Default::default(),
        }
    }
}
