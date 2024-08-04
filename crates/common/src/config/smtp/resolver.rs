/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use mail_auth::{
    common::lru::{DnsCache, LruCache},
    hickory_resolver::{
        config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
        system_conf::read_system_conf,
        AsyncResolver, TokioAsyncResolver,
    },
    Resolver,
};
use parking_lot::Mutex;
use utils::{
    config::{utils::ParseValue, Config},
    suffixlist::PublicSuffix,
};

use crate::Core;

pub struct Resolvers {
    pub dns: Resolver,
    pub dnssec: DnssecResolver,
    pub cache: DnsRecordCache,
    pub psl: PublicSuffix,
}

#[derive(Clone)]
pub struct DnssecResolver {
    pub resolver: TokioAsyncResolver,
}

pub struct DnsRecordCache {
    pub tlsa: LruCache<String, Arc<Tlsa>>,
    pub mta_sts: LruCache<String, Arc<Policy>>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct TlsaEntry {
    pub is_end_entity: bool,
    pub is_sha256: bool,
    pub is_spki: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Tlsa {
    pub entries: Vec<TlsaEntry>,
    pub has_end_entities: bool,
    pub has_intermediates: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Default, Clone, Copy)]
pub enum Mode {
    Enforce,
    Testing,
    #[default]
    None,
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<MxPattern>,
    pub max_age: u64,
}

impl Resolvers {
    pub async fn parse(config: &mut Config) -> Self {
        let (resolver_config, mut opts) = match config.value("resolver.type").unwrap_or("system") {
            "cloudflare" => (ResolverConfig::cloudflare(), ResolverOpts::default()),
            "cloudflare-tls" => (ResolverConfig::cloudflare_tls(), ResolverOpts::default()),
            "quad9" => (ResolverConfig::quad9(), ResolverOpts::default()),
            "quad9-tls" => (ResolverConfig::quad9_tls(), ResolverOpts::default()),
            "google" => (ResolverConfig::google(), ResolverOpts::default()),
            "system" => read_system_conf()
                .map_err(|err| {
                    config.new_build_error(
                        "resolver.type",
                        format!("Failed to read system DNS config: {err}"),
                    )
                })
                .unwrap_or_else(|_| (ResolverConfig::cloudflare(), ResolverOpts::default())),
            "custom" => {
                let mut resolver_config = ResolverConfig::new();
                for url in config
                    .values("resolver.custom")
                    .map(|(_, v)| v.to_string())
                    .collect::<Vec<_>>()
                {
                    let (proto, host) = if let Some((proto, host)) = url
                        .split_once("://")
                        .map(|(a, b)| (a.to_string(), b.to_string()))
                    {
                        (
                            match proto.as_str() {
                                "udp" => Protocol::Udp,
                                "tcp" => Protocol::Tcp,
                                "tls" => Protocol::Tls,
                                _ => {
                                    config.new_parse_error(
                                        "resolver.custom",
                                        format!("Invalid custom resolver protocol {url:?}"),
                                    );
                                    Protocol::Udp
                                }
                            },
                            host.to_string(),
                        )
                    } else {
                        (Protocol::Udp, url)
                    };

                    let (host, port) = if let Some(host) = host.strip_prefix('[') {
                        let (host, maybe_port) = host.rsplit_once(']').unwrap_or_default();

                        (
                            host,
                            maybe_port
                                .rsplit_once(':')
                                .map(|(_, port)| port)
                                .unwrap_or("53"),
                        )
                    } else if let Some((host, port)) = host.split_once(':') {
                        (host, port)
                    } else {
                        (host.as_str(), "53")
                    };

                    let port = port
                        .parse::<u16>()
                        .map_err(|err| {
                            config.new_parse_error(
                                "resolver.custom",
                                format!("Invalid custom resolver port {port:?}: {err}"),
                            );
                        })
                        .unwrap_or(53);

                    let host = host
                        .parse::<IpAddr>()
                        .map_err(|err| {
                            config.new_parse_error(
                                "resolver.custom",
                                format!("Invalid custom resolver IP {host:?}: {err}"),
                            )
                        })
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
                    resolver_config
                        .add_name_server(NameServerConfig::new(SocketAddr::new(host, port), proto));
                }
                if !resolver_config.name_servers().is_empty() {
                    (resolver_config, ResolverOpts::default())
                } else {
                    config.new_parse_error(
                        "resolver.custom",
                        "At least one custom resolver must be specified.",
                    );
                    (ResolverConfig::cloudflare(), ResolverOpts::default())
                }
            }
            other => {
                let err = format!("Unknown resolver type {other:?}.");
                config.new_parse_error("resolver.custom", err);
                (ResolverConfig::cloudflare(), ResolverOpts::default())
            }
        };
        if let Some(concurrency) = config.property("resolver.concurrency") {
            opts.num_concurrent_reqs = concurrency;
        }
        if let Some(timeout) = config.property("resolver.timeout") {
            opts.timeout = timeout;
        }
        if let Some(preserve) = config.property("resolver.preserve-intermediates") {
            opts.preserve_intermediates = preserve;
        }
        if let Some(try_tcp_on_error) = config.property("resolver.try-tcp-on-error") {
            opts.try_tcp_on_error = try_tcp_on_error;
        }
        if let Some(attempts) = config.property("resolver.attempts") {
            opts.attempts = attempts;
        }
        // We already have a cache, so disable the built-in cache
        opts.cache_size = 0;

        // Prepare DNSSEC resolver options
        let config_dnssec = resolver_config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        let mut capacities = [1024usize; 5];
        for (pos, key) in ["txt", "mx", "ipv4", "ipv6", "ptr"].into_iter().enumerate() {
            if let Some(capacity) = config.property(("cache.resolver", key, "size")) {
                capacities[pos] = capacity;
            }
        }

        Resolvers {
            dns: Resolver::with_capacities(
                resolver_config,
                opts,
                capacities[0],
                capacities[1],
                capacities[2],
                capacities[3],
                capacities[4],
            )
            .unwrap(),
            dnssec: DnssecResolver {
                resolver: AsyncResolver::tokio(config_dnssec, opts_dnssec),
            },
            cache: DnsRecordCache {
                tlsa: LruCache::with_capacity(
                    config.property("cache.resolver.tlsa.size").unwrap_or(1024),
                ),
                mta_sts: LruCache::with_capacity(
                    config
                        .property("cache.resolver.mta-sts.size")
                        .unwrap_or(1024),
                ),
            },
            psl: PublicSuffix::parse(config, "resolver.public-suffix").await,
        }
    }
}

impl Policy {
    pub fn try_parse(config: &mut Config) -> Option<Self> {
        let mode = config
            .property_or_default::<Option<Mode>>("session.mta-sts.mode", "testing")
            .unwrap_or_default()?;
        let max_age = config
            .property_or_default::<Duration>("session.mta-sts.max-age", "7d")
            .unwrap_or_else(|| Duration::from_secs(604800))
            .as_secs();
        let mut mx = Vec::new();

        for (_, item) in config.values("session.mta-sts.mx") {
            if let Some(item) = item.strip_prefix("*.") {
                mx.push(MxPattern::StartsWith(item.to_string()));
            } else {
                mx.push(MxPattern::Equals(item.to_string()));
            }
        }

        let mut policy = Self {
            id: Default::default(),
            mode,
            mx,
            max_age,
        };

        if !policy.mx.is_empty() {
            policy.mx.sort_unstable();
            policy.id = policy.hash().to_string();
        }

        policy.into()
    }

    pub fn try_build<I, T>(mut self, names: I) -> Option<Self>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        if self.mx.is_empty() {
            for name in names {
                let name = name.as_ref();
                if let Some(domain) = name.strip_prefix('.') {
                    self.mx.push(MxPattern::StartsWith(domain.to_string()));
                } else if name != "*" && !name.is_empty() {
                    self.mx.push(MxPattern::Equals(name.to_string()));
                }
            }

            if !self.mx.is_empty() {
                self.mx.sort_unstable();
                self.id = self.hash().to_string();
                Some(self)
            } else {
                None
            }
        } else {
            Some(self)
        }
    }

    fn hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.mode.hash(&mut s);
        self.max_age.hash(&mut s);
        self.mx.hash(&mut s);
        s.finish()
    }
}

impl Core {
    pub fn build_mta_sts_policy(&self) -> Option<Policy> {
        self.smtp.session.mta_sts_policy.clone().and_then(|policy| {
            policy.try_build(self.tls.certificates.load().keys().filter(|key| {
                !key.starts_with("mta-sts.")
                    && !key.starts_with("autoconfig.")
                    && !key.starts_with("autodiscover.")
            }))
        })
    }
}

impl ParseValue for Mode {
    fn parse_value(value: &str) -> Result<Self, String> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "testing" | "test" => Ok(Self::Testing),
            "none" => Ok(Self::None),
            _ => Err(format!("Invalid mode value {value:?}")),
        }
    }
}

impl Default for Resolvers {
    fn default() -> Self {
        let (config, opts) = match read_system_conf() {
            Ok(conf) => conf,
            Err(_) => (ResolverConfig::cloudflare(), ResolverOpts::default()),
        };

        let config_dnssec = config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        Self {
            dns: Resolver::with_capacities(config, opts, 1024, 1024, 1024, 1024, 1024)
                .expect("Failed to build DNS resolver"),
            dnssec: DnssecResolver {
                resolver: AsyncResolver::tokio(config_dnssec, opts_dnssec),
            },
            cache: DnsRecordCache {
                tlsa: LruCache::with_capacity(1024),
                mta_sts: LruCache::with_capacity(1024),
            },
            psl: PublicSuffix::default(),
        }
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("version: STSv1\r\n")?;
        f.write_str("mode: ")?;
        match self.mode {
            Mode::Enforce => f.write_str("enforce")?,
            Mode::Testing => f.write_str("testing")?,
            Mode::None => unreachable!(),
        }
        f.write_str("\r\nmax_age: ")?;
        self.max_age.fmt(f)?;
        f.write_str("\r\n")?;

        for mx in &self.mx {
            f.write_str("mx: ")?;
            mx.fmt(f)?;
            f.write_str("\r\n")?;
        }

        Ok(())
    }
}

impl Display for MxPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MxPattern::Equals(mx) => f.write_str(mx),
            MxPattern::StartsWith(mx) => {
                f.write_str("*.")?;
                f.write_str(mx)
            }
        }
    }
}

impl Clone for Resolvers {
    fn clone(&self) -> Self {
        Self {
            dns: self.dns.clone(),
            dnssec: self.dnssec.clone(),
            cache: self.cache.clone(),
            psl: self.psl.clone(),
        }
    }
}

impl Clone for DnsRecordCache {
    fn clone(&self) -> Self {
        Self {
            tlsa: Mutex::new(self.tlsa.lock().clone()),
            mta_sts: Mutex::new(self.mta_sts.lock().clone()),
        }
    }
}
