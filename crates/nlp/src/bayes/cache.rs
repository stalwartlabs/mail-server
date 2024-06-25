/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    hash::BuildHasherDefault,
    time::{Duration, Instant},
};

use lru_cache::LruCache;
use nohash::NoHashHasher;
use parking_lot::Mutex;

use super::{TokenHash, Weights};

#[derive(Debug)]
pub struct BayesTokenCache {
    positive: Mutex<LruCache<TokenHash, CacheItem, BuildHasherDefault<NoHashHasher<TokenHash>>>>,
    negative: Mutex<LruCache<TokenHash, Instant, BuildHasherDefault<NoHashHasher<TokenHash>>>>,
    ttl_negative: Duration,
    ttl_positive: Duration,
}

#[derive(Debug, Clone)]
pub struct CacheItem {
    item: Weights,
    valid_until: Instant,
}

impl BayesTokenCache {
    pub fn new(capacity: usize, ttl_positive: Duration, ttl_negative: Duration) -> Self {
        Self {
            positive: Mutex::new(LruCache::with_hasher(capacity, Default::default())),
            negative: Mutex::new(LruCache::with_hasher(capacity, Default::default())),
            ttl_negative,
            ttl_positive,
        }
    }

    pub fn get(&self, hash: &TokenHash) -> Option<Option<Weights>> {
        {
            let mut pos_cache = self.positive.lock();
            if let Some(entry) = pos_cache.get_mut(hash) {
                return if entry.valid_until >= Instant::now() {
                    Some(Some(entry.item))
                } else {
                    pos_cache.remove(hash);
                    None
                };
            }
        }
        {
            let mut neg_cache = self.negative.lock();
            if let Some(entry) = neg_cache.get_mut(hash) {
                return if *entry >= Instant::now() {
                    Some(None)
                } else {
                    neg_cache.remove(hash);
                    None
                };
            }
        }

        None
    }

    pub fn insert_positive(&self, hash: TokenHash, weights: Weights) {
        self.positive.lock().insert(
            hash,
            CacheItem {
                item: weights,
                valid_until: Instant::now() + self.ttl_positive,
            },
        );
    }

    pub fn insert_negative(&self, hash: TokenHash) {
        self.negative
            .lock()
            .insert(hash, Instant::now() + self.ttl_negative);
    }

    pub fn invalidate(&self, hash: &TokenHash) {
        if self.positive.lock().remove(hash).is_none() {
            self.negative.lock().remove(hash);
        }
    }
}

impl Default for BayesTokenCache {
    fn default() -> Self {
        Self {
            positive: Mutex::new(LruCache::with_hasher(1024, Default::default())),
            negative: Mutex::new(LruCache::with_hasher(1024, Default::default())),
            ttl_negative: Default::default(),
            ttl_positive: Default::default(),
        }
    }
}

impl Clone for BayesTokenCache {
    fn clone(&self) -> Self {
        Self {
            positive: Mutex::new(self.positive.lock().clone()),
            negative: Mutex::new(self.negative.lock().clone()),
            ttl_negative: self.ttl_negative,
            ttl_positive: self.ttl_positive,
        }
    }
}
