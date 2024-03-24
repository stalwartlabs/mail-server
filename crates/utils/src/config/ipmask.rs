/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustls::{crypto::ring::cipher_suite::*, SupportedCipherSuite};

use super::utils::{AsKey, ParseKey, ParseValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrOrMask {
    Ip(IpAddr),
    Mask(IpAddrMask),
}

impl IpAddrMask {
    pub fn matches(&self, remote: &IpAddr) -> bool {
        match self {
            IpAddrMask::V4 { addr, mask } => match *mask {
                u32::MAX => match remote {
                    IpAddr::V4(remote) => addr == remote,
                    IpAddr::V6(remote) => {
                        if let Some(remote) = remote.to_ipv4_mapped() {
                            addr == &remote
                        } else {
                            false
                        }
                    }
                },
                0 => {
                    matches!(remote, IpAddr::V4(_))
                }
                _ => {
                    u32::from_be_bytes(match remote {
                        IpAddr::V4(ip) => ip.octets(),
                        IpAddr::V6(ip) => {
                            if let Some(ip) = ip.to_ipv4() {
                                ip.octets()
                            } else {
                                return false;
                            }
                        }
                    }) & mask
                        == u32::from_be_bytes(addr.octets()) & mask
                }
            },
            IpAddrMask::V6 { addr, mask } => match *mask {
                u128::MAX => match remote {
                    IpAddr::V6(remote) => remote == addr,
                    IpAddr::V4(remote) => &remote.to_ipv6_mapped() == addr,
                },
                0 => {
                    matches!(remote, IpAddr::V6(_))
                }
                _ => {
                    u128::from_be_bytes(match remote {
                        IpAddr::V6(ip) => ip.octets(),
                        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    }) & mask
                        == u128::from_be_bytes(addr.octets()) & mask
                }
            },
        }
    }
}

impl ParseValue for IpAddrMask {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((addr, mask)) = value.rsplit_once('/') {
            if let (Ok(addr), Ok(mask)) =
                (addr.trim().parse::<IpAddr>(), mask.trim().parse::<u32>())
            {
                match addr {
                    IpAddr::V4(addr) if (8..=32).contains(&mask) => {
                        return Ok(IpAddrMask::V4 {
                            addr,
                            mask: u32::MAX << (32 - mask),
                        })
                    }
                    IpAddr::V6(addr) if (8..=128).contains(&mask) => {
                        return Ok(IpAddrMask::V6 {
                            addr,
                            mask: u128::MAX << (128 - mask),
                        })
                    }
                    _ => (),
                }
            }
        } else {
            match value.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(addr)) => {
                    return Ok(IpAddrMask::V4 {
                        addr,
                        mask: u32::MAX,
                    })
                }
                Ok(IpAddr::V6(addr)) => {
                    return Ok(IpAddrMask::V6 {
                        addr,
                        mask: u128::MAX,
                    })
                }
                _ => (),
            }
        }

        Err(format!(
            "Invalid IP address {:?} for property {:?}.",
            value,
            key.as_key()
        ))
    }
}

impl ParseValue for IpAddrOrMask {
    fn parse_value(key: impl AsKey, ip: &str) -> super::Result<Self> {
        if ip.contains('/') {
            ip.parse_key(key).map(IpAddrOrMask::Mask)
        } else {
            ip.parse_key(key).map(IpAddrOrMask::Ip)
        }
    }
}

impl ParseValue for SocketAddr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value.parse().map_err(|_| {
            format!(
                "Invalid socket address {:?} for property {:?}.",
                value,
                key.as_key()
            )
        })
    }
}

impl ParseValue for SupportedCipherSuite {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            // TLS1.3 suites
            "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
            "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
            "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
            // TLS1.2 suites
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            cipher => {
                return Err(format!(
                    "Unsupported TLS cipher suite {:?} found in key {:?}",
                    cipher,
                    key.as_key()
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipaddrmask() {
        for (mask, ip) in [
            ("10.0.0.0/8", "10.30.20.11"),
            ("10.0.0.0/8", "10.0.13.73"),
            ("192.168.1.1", "192.168.1.1"),
        ] {
            let mask = IpAddrMask::parse_value("test", mask).unwrap();
            let ip = ip.parse::<IpAddr>().unwrap();
            assert!(mask.matches(&ip));
        }

        for (mask, ip) in [
            ("10.0.0.0/8", "11.30.20.11"),
            ("192.168.1.1", "193.168.1.1"),
        ] {
            let mask = IpAddrMask::parse_value("test", mask).unwrap();
            let ip = ip.parse::<IpAddr>().unwrap();
            assert!(!mask.matches(&ip));
        }
    }
}
