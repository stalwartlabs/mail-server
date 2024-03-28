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

use std::{fmt::Debug, net::IpAddr};

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
    ip_networks: Vec<IpAddrMask>,
    has_networks: bool,
    limiter_rate: Option<Rate>,
}

pub const BLOCKED_IP_KEY: &str = "server.blocked-ip";
pub const BLOCKED_IP_PREFIX: &str = "server.blocked-ip.";

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
            limiter_rate: config.property::<Rate>("authentication.fail2ban"),
        }
    }
}

impl Core {
    pub async fn is_fail2banned(&self, ip: IpAddr, login: String) -> store::Result<bool> {
        if let Some(rate) = &self.network.blocked_ips.limiter_rate {
            let is_allowed = self
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
                    .is_none();
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
}

impl Default for BlockedIps {
    fn default() -> Self {
        Self {
            ip_addresses: RwLock::new(AHashSet::new()),
            ip_networks: Default::default(),
            has_networks: Default::default(),
            limiter_rate: Default::default(),
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
