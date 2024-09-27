/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet, RandomState};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use mail_send::smtp::tls::build_tls_connector;
use nlp::bayes::cache::BayesTokenCache;
use parking_lot::RwLock;
use utils::{
    config::Config,
    lru_cache::{LruCache, LruCached},
    map::ttl_dashmap::{TtlDashMap, TtlMap},
    snowflake::SnowflakeIdGenerator,
};

use crate::{
    listener::blocked::BlockedIps, manager::webadmin::WebAdminManager, Data,
    ThrottleKeyHasherBuilder, TlsConnectors,
};

use super::server::tls::{build_self_signed_cert, parse_certificates};

impl Data {
    pub fn parse(config: &mut Config) -> Self {
        // Parse certificates
        let mut certificates = AHashMap::new();
        let mut subject_names = AHashSet::new();
        parse_certificates(config, &mut certificates, &mut subject_names);
        if subject_names.is_empty() {
            subject_names.insert("localhost".to_string());
        }

        // Parse capacities
        let shard_amount = config
            .property::<u64>("cache.shard")
            .unwrap_or(32)
            .next_power_of_two() as usize;
        let capacity = config.property("cache.capacity").unwrap_or(100);

        // Parse id generator
        let id_generator = config
            .property::<u64>("cluster.node-id")
            .map(SnowflakeIdGenerator::with_node_id)
            .unwrap_or_default();

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
            access_tokens: TtlDashMap::with_capacity(capacity, shard_amount),
            http_auth_cache: TtlDashMap::with_capacity(capacity, shard_amount),
            blocked_ips: RwLock::new(BlockedIps::parse(config).blocked_ip_addresses),
            blocked_ips_version: 0.into(),
            permissions: Default::default(),
            permissions_version: 0.into(),
            jmap_id_gen: id_generator.clone(),
            queue_id_gen: id_generator.clone(),
            span_id_gen: id_generator,
            webadmin: config
                .value("webadmin.path")
                .map(|path| WebAdminManager::new(path.into()))
                .unwrap_or_default(),
            config_version: 0.into(),
            jmap_limiter: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                RandomState::default(),
                shard_amount,
            ),
            imap_limiter: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                RandomState::default(),
                shard_amount,
            ),
            account_cache: LruCache::with_capacity(
                config.property("cache.account.size").unwrap_or(2048),
            ),
            mailbox_cache: LruCache::with_capacity(
                config.property("cache.mailbox.size").unwrap_or(2048),
            ),
            threads_cache: LruCache::with_capacity(
                config.property("cache.thread.size").unwrap_or(2048),
            ),
            logos: Default::default(),
            smtp_session_throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                ThrottleKeyHasherBuilder::default(),
                shard_amount,
            ),
            smtp_queue_throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                capacity,
                ThrottleKeyHasherBuilder::default(),
                shard_amount,
            ),
            smtp_connectors: TlsConnectors::default(),
            bayes_cache: BayesTokenCache::new(
                config
                    .property_or_default("cache.bayes.capacity", "8192")
                    .unwrap_or(8192),
                config
                    .property_or_default("cache.bayes.ttl.positive", "1h")
                    .unwrap_or_else(|| Duration::from_secs(3600)),
                config
                    .property_or_default("cache.bayes.ttl.negative", "1h")
                    .unwrap_or_else(|| Duration::from_secs(3600)),
            ),
            remote_lists: Default::default(),
        }
    }
}

impl Default for Data {
    fn default() -> Self {
        Self {
            tls_certificates: Default::default(),
            tls_self_signed_cert: Default::default(),
            access_tokens: Default::default(),
            http_auth_cache: Default::default(),
            blocked_ips: Default::default(),
            blocked_ips_version: 0.into(),
            permissions: Default::default(),
            permissions_version: 0.into(),
            remote_lists: Default::default(),
            jmap_id_gen: Default::default(),
            queue_id_gen: Default::default(),
            span_id_gen: Default::default(),
            webadmin: Default::default(),
            config_version: Default::default(),
            jmap_limiter: Default::default(),
            imap_limiter: Default::default(),
            account_cache: LruCache::with_capacity(2048),
            mailbox_cache: LruCache::with_capacity(2048),
            threads_cache: LruCache::with_capacity(2048),
            logos: Default::default(),
            smtp_session_throttle: Default::default(),
            smtp_queue_throttle: Default::default(),
            smtp_connectors: Default::default(),
            bayes_cache: BayesTokenCache::new(
                8192,
                Duration::from_secs(3600),
                Duration::from_secs(3600),
            ),
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
