/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Debug, net::IpAddr, sync::atomic::AtomicU8};

use ahash::AHashSet;
use parking_lot::RwLock;
use utils::config::{
    ipmask::{IpAddrMask, IpAddrOrMask},
    utils::ParseValue,
    Config, ConfigKey, Rate,
};

use crate::Core;

pub struct BlockedIps {
    pub ip_addresses: RwLock<AHashSet<IpAddr>>,
    pub version: AtomicU8,
    ip_networks: Vec<IpAddrMask>,
    has_networks: bool,
    limiter_rate: Option<Rate>,
}

#[derive(Clone)]
pub struct AllowedIps {
    ip_addresses: AHashSet<IpAddr>,
    ip_networks: Vec<IpAddrMask>,
    has_networks: bool,
}

pub const BLOCKED_IP_KEY: &str = "server.blocked-ip";
pub const BLOCKED_IP_PREFIX: &str = "server.blocked-ip.";
pub const ALLOWED_IP_KEY: &str = "server.allowed-ip";
pub const ALLOWED_IP_PREFIX: &str = "server.allowed-ip.";

impl BlockedIps {
    pub fn parse(config: &mut Config) -> Self {
        let mut ip_addresses = AHashSet::new();
        let mut ip_networks = Vec::new();

        for ip in config
            .set_values(BLOCKED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(ip)) => {
                    ip_networks.push(ip);
                }
                Err(err) => {
                    config.new_parse_error(BLOCKED_IP_KEY, err);
                }
            }
        }

        BlockedIps {
            ip_addresses: RwLock::new(ip_addresses),
            has_networks: !ip_networks.is_empty(),
            ip_networks,
            limiter_rate: config.property_or_default::<Rate>("authentication.fail2ban", "100/1d"),
            version: 0.into(),
        }
    }
}

impl AllowedIps {
    pub fn parse(config: &mut Config) -> Self {
        let mut ip_addresses = AHashSet::new();
        let mut ip_networks = Vec::new();

        for ip in config
            .set_values(ALLOWED_IP_KEY)
            .map(IpAddrOrMask::parse_value)
            .collect::<Vec<_>>()
        {
            match ip {
                Ok(IpAddrOrMask::Ip(ip)) => {
                    ip_addresses.insert(ip);
                }
                Ok(IpAddrOrMask::Mask(ip)) => {
                    ip_networks.push(ip);
                }
                Err(err) => {
                    config.new_parse_error(ALLOWED_IP_KEY, err);
                }
            }
        }

        #[cfg(not(feature = "test_mode"))]
        {
            // Add loopback addresses
            ip_addresses.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            ip_addresses.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        }

        AllowedIps {
            ip_addresses,
            has_networks: !ip_networks.is_empty(),
            ip_networks,
        }
    }
}

impl Core {
    pub async fn is_fail2banned(&self, ip: IpAddr, login: String) -> store::Result<bool> {
        if let Some(rate) = &self.network.blocked_ips.limiter_rate {
            let is_allowed = self.is_ip_allowed(&ip)
                || (self
                    .storage
                    .lookup
                    .is_rate_allowed(format!("b:{}", ip).as_bytes(), rate, false)
                    .await?
                    .is_none()
                    && self
                        .storage
                        .lookup
                        .is_rate_allowed(format!("b:{}", login).as_bytes(), rate, false)
                        .await?
                        .is_none());
            if !is_allowed {
                // Add IP to blocked list
                self.network.blocked_ips.ip_addresses.write().insert(ip);

                // Write blocked IP to config
                self.storage
                    .config
                    .set([ConfigKey {
                        key: format!("{}.{}", BLOCKED_IP_KEY, ip),
                        value: String::new(),
                    }])
                    .await?;

                // Increment version
                self.network.blocked_ips.increment_version();

                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn has_fail2ban(&self) -> bool {
        self.network.blocked_ips.limiter_rate.is_some()
    }

    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.network.blocked_ips.ip_addresses.read().contains(ip)
            || (self.network.blocked_ips.has_networks
                && self
                    .network
                    .blocked_ips
                    .ip_networks
                    .iter()
                    .any(|network| network.matches(ip)))
    }

    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.network.allowed_ips.ip_addresses.contains(ip)
            || (self.network.allowed_ips.has_networks
                && self
                    .network
                    .allowed_ips
                    .ip_networks
                    .iter()
                    .any(|network| network.matches(ip)))
    }
}

impl BlockedIps {
    pub fn increment_version(&self) {
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for BlockedIps {
    fn default() -> Self {
        Self {
            ip_addresses: RwLock::new(AHashSet::new()),
            ip_networks: Default::default(),
            has_networks: Default::default(),
            limiter_rate: Default::default(),
            version: Default::default(),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for AllowedIps {
    fn default() -> Self {
        // Add IPv4 and IPv6 loopback addresses
        Self {
            #[cfg(not(feature = "test_mode"))]
            ip_addresses: AHashSet::from_iter([
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ]),
            #[cfg(feature = "test_mode")]
            ip_addresses: Default::default(),
            ip_networks: Default::default(),
            has_networks: Default::default(),
        }
    }
}

impl Clone for BlockedIps {
    fn clone(&self) -> Self {
        Self {
            ip_addresses: RwLock::new(self.ip_addresses.read().clone()),
            ip_networks: self.ip_networks.clone(),
            has_networks: self.has_networks,
            limiter_rate: self.limiter_rate.clone(),
            version: self
                .version
                .load(std::sync::atomic::Ordering::Relaxed)
                .into(),
        }
    }
}

impl Debug for BlockedIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockedIps")
            .field("ip_addresses", &self.ip_addresses)
            .field("ip_networks", &self.ip_networks)
            .field("limiter_rate", &self.limiter_rate)
            .finish()
    }
}
