use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
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
use utils::{config::Config, suffixlist::PublicSuffix};

pub struct Resolvers {
    pub dns: Resolver,
    pub dnssec: DnssecResolver,
    pub cache: DnsRecordCache,
    pub psl: PublicSuffix,
}

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

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<MxPattern>,
    pub max_age: u64,
}

impl Resolvers {
    pub async fn parse(config: &mut Config) -> Self {
        let (resolver_config, mut opts) = match config
            .value_require_("resolver.type")
            .unwrap_or("system")
        {
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
                    let (host, port) = if let Some((host, port)) = host.split_once(':') {
                        (
                            host.to_string(),
                            port.parse::<u16>()
                                .map_err(|err| {
                                    config.new_parse_error(
                                        "resolver.custom",
                                        format!("Invalid custom resolver port {port:?}: {err}"),
                                    );
                                })
                                .unwrap_or(53),
                        )
                    } else {
                        (host, 53)
                    };
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
        if let Some(concurrency) = config.property_("resolver.concurrency") {
            opts.num_concurrent_reqs = concurrency;
        }
        if let Some(timeout) = config.property_("resolver.timeout") {
            opts.timeout = timeout;
        }
        if let Some(preserve) = config.property_("resolver.preserve-intermediates") {
            opts.preserve_intermediates = preserve;
        }
        if let Some(try_tcp_on_error) = config.property_("resolver.try-tcp-on-error") {
            opts.try_tcp_on_error = try_tcp_on_error;
        }
        if let Some(attempts) = config.property_("resolver.attempts") {
            opts.attempts = attempts;
        }

        // Prepare DNSSEC resolver options
        let config_dnssec = resolver_config.clone();
        let mut opts_dnssec = opts.clone();
        opts_dnssec.validate = true;

        let mut capacities = [1024usize; 5];
        for (pos, key) in ["txt", "mx", "ipv4", "ipv6", "ptr"].into_iter().enumerate() {
            if let Some(capacity) = config.property_(("cache.resolver", key)) {
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
                    config.property_("cache.resolver.tlsa.size").unwrap_or(1024),
                ),
                mta_sts: LruCache::with_capacity(
                    config
                        .property_("cache.resolver.mta-sts.size")
                        .unwrap_or(1024),
                ),
            },
            psl: PublicSuffix::parse(config, "resolver.public-suffix").await,
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
