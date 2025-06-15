/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::server::tls::{build_self_signed_cert, parse_certificates};
use crate::{
    CacheSwap, Caches, Data, DavResource, DavResources, MailboxCache, MessageStoreCache,
    MessageUidCache, TlsConnectors,
    auth::{AccessToken, roles::RolePermissions},
    config::smtp::resolver::{Policy, Tlsa},
    listener::blocked::BlockedIps,
    manager::webadmin::WebAdminManager,
};
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use mail_auth::{MX, Parameters, Txt};
use mail_send::smtp::tls::build_tls_connector;
use nlp::bayes::{TokenHash, Weights};
use parking_lot::RwLock;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use utils::{
    cache::{Cache, CacheWithTtl},
    config::Config,
    snowflake::SnowflakeIdGenerator,
};

impl Data {
    pub fn parse(config: &mut Config) -> Self {
        // Parse certificates
        let mut certificates = AHashMap::new();
        let mut subject_names = AHashSet::new();
        parse_certificates(config, &mut certificates, &mut subject_names);
        if subject_names.is_empty() {
            subject_names.insert("localhost".to_string());
        }

        // Build and test snowflake id generator
        let node_id = config
            .property::<u64>("cluster.node-id")
            .unwrap_or_else(store::rand::random);
        let id_generator = SnowflakeIdGenerator::with_node_id(node_id);
        if !id_generator.is_valid() {
            panic!("Invalid system time, panicking to avoid data corruption");
        }

        Data {
            tls_certificates: ArcSwap::from_pointee(certificates),
            tls_self_signed_cert: build_self_signed_cert(
                subject_names.into_iter().collect::<Vec<_>>(),
            )
            .or_else(|err| {
                config.new_build_error("certificate.self-signed", err);
                build_self_signed_cert(vec!["localhost".to_string()])
            })
            .ok()
            .map(Arc::new),
            blocked_ips: RwLock::new(BlockedIps::parse(config).blocked_ip_addresses),
            jmap_id_gen: id_generator.clone(),
            queue_id_gen: id_generator.clone(),
            span_id_gen: id_generator,
            queue_status: true.into(),
            webadmin: config
                .value("webadmin.path")
                .map(|path| WebAdminManager::new(path.into()))
                .unwrap_or_default(),
            logos: Default::default(),
            smtp_connectors: TlsConnectors::default(),
            asn_geo_data: Default::default(),
        }
    }
}

impl Caches {
    pub fn parse(config: &mut Config) -> Self {
        const MB_50: u64 = 50 * 1024 * 1024;
        const MB_10: u64 = 10 * 1024 * 1024;
        const MB_5: u64 = 5 * 1024 * 1024;
        const MB_1: u64 = 1024 * 1024;

        Caches {
            access_tokens: Cache::from_config(
                config,
                "access-token",
                MB_10,
                (std::mem::size_of::<AccessToken>() + 255) as u64,
            ),
            http_auth: Cache::from_config(
                config,
                "http-auth",
                MB_1,
                (50 + std::mem::size_of::<u32>()) as u64,
            ),
            permissions: Cache::from_config(
                config,
                "permission",
                MB_5,
                std::mem::size_of::<RolePermissions>() as u64,
            ),
            messages: Cache::from_config(
                config,
                "message",
                MB_50,
                (std::mem::size_of::<u32>()
                    + std::mem::size_of::<CacheSwap<MessageStoreCache>>()
                    + (1024 * std::mem::size_of::<MessageUidCache>())
                    + (15 * (std::mem::size_of::<MailboxCache>() + 60))) as u64,
            ),
            files: Cache::from_config(
                config,
                "files",
                MB_10,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            events: Cache::from_config(
                config,
                "events",
                MB_10,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            contacts: Cache::from_config(
                config,
                "contacts",
                MB_10,
                (std::mem::size_of::<DavResources>() + (500 * std::mem::size_of::<DavResource>()))
                    as u64,
            ),
            bayes: CacheWithTtl::from_config(
                config,
                "bayes",
                MB_10,
                (std::mem::size_of::<TokenHash>() + std::mem::size_of::<Weights>()) as u64,
            ),
            dns_txt: CacheWithTtl::from_config(
                config,
                "dns.txt",
                MB_5,
                (std::mem::size_of::<Txt>() + 255) as u64,
            ),
            dns_mx: CacheWithTtl::from_config(
                config,
                "dns.mx",
                MB_5,
                ((std::mem::size_of::<MX>() + 255) * 2) as u64,
            ),
            dns_ptr: CacheWithTtl::from_config(
                config,
                "dns.ptr",
                MB_1,
                (std::mem::size_of::<IpAddr>() + 255) as u64,
            ),
            dns_ipv4: CacheWithTtl::from_config(
                config,
                "dns.ipv4",
                MB_5,
                ((std::mem::size_of::<Ipv4Addr>() + 255) * 2) as u64,
            ),
            dns_ipv6: CacheWithTtl::from_config(
                config,
                "dns.ipv6",
                MB_5,
                ((std::mem::size_of::<Ipv6Addr>() + 255) * 2) as u64,
            ),
            dns_tlsa: CacheWithTtl::from_config(
                config,
                "dns.tlsa",
                MB_1,
                (std::mem::size_of::<Tlsa>() + 255) as u64,
            ),
            dbs_mta_sts: CacheWithTtl::from_config(
                config,
                "dns.mta-sts",
                MB_1,
                (std::mem::size_of::<Policy>() + 255) as u64,
            ),
            dns_rbl: CacheWithTtl::from_config(
                config,
                "dns.rbl",
                MB_5,
                ((std::mem::size_of::<Ipv4Addr>() + 255) * 2) as u64,
            ),
        }
    }

    #[allow(clippy::type_complexity)]
    #[inline(always)]
    pub fn build_auth_parameters<T>(
        &self,
        params: T,
    ) -> Parameters<
        '_,
        T,
        CacheWithTtl<String, Txt>,
        CacheWithTtl<String, Arc<Vec<MX>>>,
        CacheWithTtl<String, Arc<Vec<Ipv4Addr>>>,
        CacheWithTtl<String, Arc<Vec<Ipv6Addr>>>,
        CacheWithTtl<IpAddr, Arc<Vec<String>>>,
    > {
        Parameters {
            params,
            cache_txt: Some(&self.dns_txt),
            cache_mx: Some(&self.dns_mx),
            cache_ptr: Some(&self.dns_ptr),
            cache_ipv4: Some(&self.dns_ipv4),
            cache_ipv6: Some(&self.dns_ipv6),
        }
    }
}

impl Default for Data {
    fn default() -> Self {
        Self {
            tls_certificates: Default::default(),
            tls_self_signed_cert: Default::default(),
            blocked_ips: Default::default(),
            jmap_id_gen: Default::default(),
            queue_id_gen: Default::default(),
            span_id_gen: Default::default(),
            queue_status: true.into(),
            webadmin: Default::default(),
            logos: Default::default(),
            smtp_connectors: Default::default(),
            asn_geo_data: Default::default(),
        }
    }
}

impl Default for TlsConnectors {
    fn default() -> Self {
        TlsConnectors {
            pki_verify: build_tls_connector(false),
            dummy_verify: build_tls_connector(true),
        }
    }
}
