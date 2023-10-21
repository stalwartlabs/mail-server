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

use std::io::Read;

use mail_auth::{
    common::lru::{DnsCache, LruCache},
    flate2::read::GzDecoder,
    hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        system_conf::read_system_conf,
    },
    Resolver,
};

use crate::{core::Resolvers, outbound::dane::DnssecResolver};
use utils::{config::Config, suffixlist::PublicSuffix};

pub trait ConfigResolver {
    fn build_resolvers(&self) -> super::Result<Resolvers>;
    fn parse_public_suffix(&self) -> super::Result<PublicSuffix>;
}

impl ConfigResolver for Config {
    fn build_resolvers(&self) -> super::Result<Resolvers> {
        let (config, mut opts) = match self.value_require("resolver.type")? {
            "cloudflare" => (ResolverConfig::cloudflare(), ResolverOpts::default()),
            "cloudflare-tls" => (ResolverConfig::cloudflare_tls(), ResolverOpts::default()),
            "quad9" => (ResolverConfig::quad9(), ResolverOpts::default()),
            "quad9-tls" => (ResolverConfig::quad9_tls(), ResolverOpts::default()),
            "google" => (ResolverConfig::google(), ResolverOpts::default()),
            "system" => read_system_conf()
                .map_err(|err| format!("Failed to read system DNS config: {err}"))?,
            other => return Err(format!("Unknown resolver type {other:?}.")),
        };
        if let Some(concurrency) = self.property("resolver.concurrency")? {
            opts.num_concurrent_reqs = concurrency;
        }
        if let Some(timeout) = self.property("resolver.timeout")? {
            opts.timeout = timeout;
        }
        if let Some(preserve) = self.property("resolver.preserve-intermediates")? {
            opts.preserve_intermediates = preserve;
        }
        if let Some(try_tcp_on_error) = self.property("resolver.try-tcp-on-error")? {
            opts.try_tcp_on_error = try_tcp_on_error;
        }
        if let Some(attempts) = self.property("resolver.attempts")? {
            opts.attempts = attempts;
        }

        // Prepare DNSSEC resolver options
        let config_dnssec = config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        let mut capacities = [1024usize; 5];
        for (pos, key) in ["txt", "mx", "ipv4", "ipv6", "ptr"].into_iter().enumerate() {
            if let Some(capacity) = self.property(("resolver.cache", key))? {
                capacities[pos] = capacity;
            }
        }

        Ok(Resolvers {
            dns: Resolver::with_capacities(
                config,
                opts,
                capacities[0],
                capacities[1],
                capacities[2],
                capacities[3],
                capacities[4],
            )
            .map_err(|err| format!("Failed to build DNS resolver: {err}"))?,
            dnssec: DnssecResolver::with_capacity(config_dnssec, opts_dnssec)
                .map_err(|err| format!("Failed to build DNSSEC resolver: {err}"))?,
            cache: crate::core::DnsCache {
                tlsa: LruCache::with_capacity(
                    self.property("resolver.cache.tlsa")?.unwrap_or(1024),
                ),
                mta_sts: LruCache::with_capacity(
                    self.property("resolver.cache.mta-sts")?.unwrap_or(1024),
                ),
            },
        })
    }

    fn parse_public_suffix(&self) -> super::Result<PublicSuffix> {
        let mut has_values = false;
        for (_, value) in self.values("resolver.public-suffix") {
            has_values = true;
            let bytes = if value.starts_with("https://") || value.starts_with("http://") {
                match tokio::task::block_in_place(|| {
                    reqwest::blocking::get(value).and_then(|r| {
                        if r.status().is_success() {
                            r.bytes().map(Ok)
                        } else {
                            Ok(Err(r))
                        }
                    })
                }) {
                    Ok(Ok(bytes)) => bytes.to_vec(),
                    Ok(Err(response)) => {
                        tracing::warn!(
                            "Failed to fetch public suffixes from {value:?}: Status {status}",
                            value = value,
                            status = response.status()
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to fetch public suffixes from {value:?}: {err}",
                            value = value,
                            err = err
                        );
                        continue;
                    }
                }
            } else if let Some(filename) = value.strip_prefix("file://") {
                match std::fs::read(filename) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::warn!(
                            "Failed to read public suffixes from {value:?}: {err}",
                            value = value,
                            err = err
                        );
                        continue;
                    }
                }
            } else {
                return Err(format!("Invalid public suffix file {value:?}"));
            };
            let bytes = if value.ends_with(".gz") {
                match GzDecoder::new(&bytes[..])
                    .bytes()
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::warn!(
                            "Failed to decompress public suffixes from {value:?}: {err}",
                            value = value,
                            err = err
                        );
                        continue;
                    }
                }
            } else {
                bytes
            };

            match String::from_utf8(bytes) {
                Ok(list) => {
                    return Ok(PublicSuffix::from(list.as_str()));
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to parse public suffixes from {value:?}: {err}",
                        value = value,
                        err = err
                    );
                }
            }
        }

        if has_values {
            tracing::warn!("Failed to parse public suffixes from any source.");
        } else {
            tracing::warn!("No public suffixes list was specified.");
        }

        Ok(PublicSuffix::default())
    }
}
