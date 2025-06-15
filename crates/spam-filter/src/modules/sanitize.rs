/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use compact_str::CompactString;

use crate::{Email, Hostname};

impl Hostname {
    pub fn new(host: &str) -> Self {
        let mut fqdn = CompactString::from_str_to_lowercase(host.trim_end_matches('.'));

        // Decode punycode
        if fqdn.contains("xn--") {
            let mut decoded = CompactString::with_capacity(fqdn.len());

            for part in fqdn.split('.') {
                if !decoded.is_empty() {
                    decoded.push('.');
                }

                if let Some(puny) = part
                    .strip_prefix("xn--")
                    .and_then(idna::punycode::decode_to_string)
                {
                    decoded.push_str(&puny);
                } else {
                    decoded.push_str(part);
                }
            }

            fqdn = decoded;
        }

        let ip = fqdn
            .strip_prefix('[')
            .and_then(|ip| ip.strip_suffix(']'))
            .unwrap_or(&fqdn)
            .parse::<IpAddr>()
            .ok();

        Hostname {
            sld: if ip.is_none() {
                psl::domain(fqdn.as_bytes()).and_then(|domain| {
                    if domain.suffix().typ().is_some() {
                        std::str::from_utf8(domain.as_bytes()).ok().map(Into::into)
                    } else {
                        None
                    }
                })
            } else {
                None
            },
            ip,
            fqdn,
        }
    }
}

impl Email {
    pub fn new(address: &str) -> Self {
        let address = CompactString::from_str_to_lowercase(address);
        let (local_part, domain) = address.rsplit_once('@').unwrap_or_default();

        Email {
            local_part: local_part.into(),
            domain_part: Hostname::new(domain),
            address,
        }
    }
}

impl Hostname {
    pub fn sld_or_default(&self) -> &str {
        self.sld.as_deref().unwrap_or(self.fqdn.as_str())
    }
}
