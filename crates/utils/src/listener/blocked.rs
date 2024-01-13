/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::{
    fmt::Debug,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ahash::{AHashMap, AHashSet};
use arc_swap::{ArcSwap, ArcSwapOption};
use parking_lot::{Mutex, RwLock};

use crate::config::{ipmask::IpAddrMask, utils::ParseKey, Config, ConfigKey, Rate};

use super::limiter::RateLimiter;

pub struct BlockedIps {
    ip_addresses: RwLock<AHashSet<IpAddr>>,
    ip_networks: ArcSwap<Vec<IpAddrMask>>,
    has_networks: AtomicBool,
    limiters: Mutex<AHashMap<LimitBy, RateLimiter>>,
    limiter_rate: ArcSwapOption<Rate>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum LimitBy {
    IpAddr(IpAddr),
    Login(String),
}

pub const BLOCKED_IP_KEY: &str = "server.security.blocked-networks";

impl BlockedIps {
    pub fn new() -> Self {
        Self {
            ip_addresses: RwLock::new(AHashSet::new()),
            ip_networks: ArcSwap::new(Arc::new(Vec::new())),
            limiters: Mutex::new(Default::default()),
            limiter_rate: ArcSwapOption::empty(),
            has_networks: AtomicBool::new(false),
        }
    }

    pub fn reload(&self, config: &Config) -> crate::config::Result<()> {
        self.limiter_rate.store(
            config
                .property::<Rate>("server.security.fail2ban")?
                .map(Arc::new),
        );
        self.reload_blocked_ips(config)
    }

    pub fn reload_blocked_ips(&self, config: &Config) -> crate::config::Result<()> {
        let mut ip_addresses = AHashSet::new();
        let mut ip_networks = Vec::new();

        for ip in config.set_values(BLOCKED_IP_KEY) {
            if ip.contains('/') {
                ip_networks.push(ip.parse_key(BLOCKED_IP_KEY)?);
            } else {
                ip_addresses.insert(ip.parse_key(BLOCKED_IP_KEY)?);
            }
        }

        self.has_networks
            .store(!ip_networks.is_empty(), Ordering::Relaxed);
        *self.ip_addresses.write() = ip_addresses;
        self.ip_networks.store(Arc::new(ip_networks));

        Ok(())
    }

    pub fn is_fail2banned(&self, ip: IpAddr, login: String) -> Option<ConfigKey> {
        if let Some(rate) = self.limiter_rate.load().as_ref() {
            let is_allowed = self
                .limiters
                .lock()
                .entry(LimitBy::IpAddr(ip))
                .or_insert_with(|| RateLimiter::new(rate))
                .is_allowed(rate)
                && self
                    .limiters
                    .lock()
                    .entry(LimitBy::Login(login))
                    .or_insert_with(|| RateLimiter::new(rate))
                    .is_allowed(rate);

            if !is_allowed {
                self.ip_addresses.write().insert(ip);
                return Some(ConfigKey {
                    key: format!("{}.{}", BLOCKED_IP_KEY, ip),
                    value: String::new(),
                });
            }
        }

        None
    }

    pub fn has_fail2ban(&self) -> bool {
        self.limiter_rate.load().is_some()
    }

    pub fn cleanup(&self) {
        self.limiters
            .lock()
            .retain(|_, limiter| limiter.is_active());
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.ip_addresses.read().contains(ip)
            || (self.has_networks.load(Ordering::Relaxed)
                && self
                    .ip_networks
                    .load()
                    .iter()
                    .any(|network| network.matches(ip)))
    }
}

impl Debug for BlockedIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockedIps")
            .field("ip_addresses", &self.ip_addresses)
            .field("ip_networks", &self.ip_networks)
            .field("limiters", &self.limiters)
            .field("limiter_rate", &self.limiter_rate)
            .finish()
    }
}

impl Default for BlockedIps {
    fn default() -> Self {
        Self::new()
    }
}
