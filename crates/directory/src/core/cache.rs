/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Borrow,
    hash::Hash,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use utils::config::{utils::AsKey, Config};

pub struct CachedDirectory {
    cached_domains: Mutex<LookupCache<String>>,
    cached_rcpts: Mutex<LookupCache<String>>,
}

#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct LookupCache<T: Hash + Eq> {
    cache_pos: lru_cache::LruCache<T, Instant, ahash::RandomState>,
    cache_neg: lru_cache::LruCache<T, Instant, ahash::RandomState>,
    ttl_pos: Duration,
    ttl_neg: Duration,
}

impl CachedDirectory {
    pub fn try_from_config(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let prefix = prefix.as_key();
        let cached_entries = config.property((&prefix, "cache.entries"))?;
        let cache_ttl_positive = config
            .property((&prefix, "cache.ttl.positive"))
            .unwrap_or(Duration::from_secs(86400));
        let cache_ttl_negative = config
            .property((&prefix, "cache.ttl.negative"))
            .unwrap_or_else(|| Duration::from_secs(3600));

        Some(CachedDirectory {
            cached_domains: Mutex::new(LookupCache::new(
                cached_entries,
                cache_ttl_positive,
                cache_ttl_negative,
            )),
            cached_rcpts: Mutex::new(LookupCache::new(
                cached_entries,
                cache_ttl_positive,
                cache_ttl_negative,
            )),
        })
    }

    pub fn get_rcpt(&self, address: &str) -> Option<bool> {
        self.cached_rcpts.lock().get(address)
    }

    pub fn set_rcpt(&self, address: &str, exists: bool) {
        if exists {
            self.cached_rcpts.lock().insert_pos(address.to_string());
        } else {
            self.cached_rcpts.lock().insert_neg(address.to_string());
        }
    }

    pub fn get_domain(&self, domain: &str) -> Option<bool> {
        self.cached_domains.lock().get(domain)
    }

    pub fn set_domain(&self, domain: &str, exists: bool) {
        if exists {
            self.cached_domains.lock().insert_pos(domain.to_string());
        } else {
            self.cached_domains.lock().insert_neg(domain.to_string());
        }
    }
}

impl<T: Hash + Eq> LookupCache<T> {
    pub fn new(capacity: usize, ttl_pos: Duration, ttl_neg: Duration) -> Self {
        Self {
            cache_pos: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            cache_neg: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            ttl_pos,
            ttl_neg,
        }
    }

    pub fn get<Q>(&mut self, name: &Q) -> Option<bool>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        // Check positive cache
        if let Some(valid_until) = self.cache_pos.get_mut(name) {
            if *valid_until >= Instant::now() {
                return Some(true);
            } else {
                self.cache_pos.remove(name);
            }
        }

        // Check negative cache
        let valid_until = self.cache_neg.get_mut(name)?;
        if *valid_until >= Instant::now() {
            Some(false)
        } else {
            self.cache_pos.remove(name);
            None
        }
    }

    pub fn insert_pos(&mut self, item: T) {
        self.cache_pos.insert(item, Instant::now() + self.ttl_pos);
    }

    pub fn insert_neg(&mut self, item: T) {
        self.cache_neg.insert(item, Instant::now() + self.ttl_neg);
    }

    pub fn clear(&mut self) {
        self.cache_pos.clear();
        self.cache_neg.clear();
    }
}
