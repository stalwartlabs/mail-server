use std::sync::Arc;

use mail_auth::{
    common::lru::{DnsCache, LruCache},
    hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        system_conf::read_system_conf,
        AsyncResolver, TokioAsyncResolver,
    },
    Resolver,
};

pub struct Resolvers {
    pub dns: Resolver,
    pub dnssec: DnssecResolver,
    pub cache: DnsRecordCache,
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
        }
    }
}
