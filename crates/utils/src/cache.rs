/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Borrow,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{MX, ResolverCache, Txt};
use quick_cache::{
    Equivalent, Weighter,
    sync::{DefaultLifecycle, PlaceholderGuard},
};

use crate::config::Config;

pub struct Cache<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight>(
    quick_cache::sync::Cache<K, V, CacheItemWeighter>,
);

pub struct CacheWithTtl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight>(
    quick_cache::sync::Cache<K, TtlEntry<V>, CacheItemWeighter>,
);

#[derive(Clone)]
pub struct TtlEntry<V: Clone + CacheItemWeight> {
    value: V,
    expires: Instant,
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> Cache<K, V> {
    pub fn from_config(
        config: &mut Config,
        key: &str,
        max_weight: u64,
        estimated_weight: u64,
    ) -> Self {
        let weight_capacity = config
            .property(("cache", key, "size"))
            .unwrap_or(max_weight);
        let estimated_items_capacity = config
            .property(("cache", key, "capacity"))
            .unwrap_or_else(|| weight_capacity as usize / estimated_weight as usize);

        Self::new(estimated_items_capacity, weight_capacity)
    }

    pub fn new(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self(quick_cache::sync::Cache::with_weighter(
            estimated_items_capacity,
            weight_capacity,
            CacheItemWeighter,
        ))
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.get(key)
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<'a, K, V, CacheItemWeighter, ahash::RandomState, DefaultLifecycle<K, V>>,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        self.0.get_value_or_guard_async(key).await
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V) {
        self.0.insert(key, value);
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.remove(key).map(|(_, v)| v)
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.0.clear();
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> CacheWithTtl<K, V> {
    pub fn from_config(
        config: &mut Config,
        key: &str,
        max_weight: u64,
        estimated_weight: u64,
    ) -> Self {
        let weight_capacity = config
            .property(("cache", key, "size"))
            .unwrap_or(max_weight);
        let estimated_items_capacity = config
            .property(("cache", key, "capacity"))
            .unwrap_or_else(|| weight_capacity as usize / estimated_weight as usize);

        Self::new(estimated_items_capacity, weight_capacity)
    }

    pub fn new(estimated_items_capacity: usize, weight_capacity: u64) -> Self {
        Self(quick_cache::sync::Cache::with_weighter(
            estimated_items_capacity,
            weight_capacity,
            CacheItemWeighter,
        ))
    }

    #[inline(always)]
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.get(key).and_then(|v| {
            if v.expires > Instant::now() {
                Some(v.value)
            } else {
                self.0.remove(key);
                None
            }
        })
    }

    #[inline(always)]
    pub async fn get_value_or_guard_async<'a, Q>(
        &'a self,
        key: &Q,
    ) -> Result<
        V,
        PlaceholderGuard<
            'a,
            K,
            TtlEntry<V>,
            CacheItemWeighter,
            ahash::RandomState,
            DefaultLifecycle<K, TtlEntry<V>>,
        >,
    >
    where
        Q: Hash + Equivalent<K> + ToOwned<Owned = K> + ?Sized,
    {
        match self.0.get_value_or_guard_async(key).await {
            Ok(value) => {
                if value.expires > Instant::now() {
                    Ok(value.value)
                } else {
                    self.0.remove(key);
                    self.0.get_value_or_guard_async(key).await.map(|v| v.value)
                }
            }
            Err(err) => Err(err),
        }
    }

    #[inline(always)]
    pub fn insert(&self, key: K, value: V, expires: Duration) {
        self.0.insert(key, TtlEntry::new(value, expires));
    }

    #[inline(always)]
    pub fn insert_with_expiry(&self, key: K, value: V, expires: Instant) {
        self.0.insert(key, TtlEntry::with_expiry(value, expires));
    }

    #[inline(always)]
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.0.remove(key).map(|(_, v)| v.value)
    }

    #[inline(always)]
    pub fn clear(&self) {
        self.0.clear();
    }
}

#[derive(Clone)]
pub struct CacheItemWeighter;

impl<K: CacheItemWeight, V: CacheItemWeight> Weighter<K, V> for CacheItemWeighter {
    fn weight(&self, key: &K, val: &V) -> u64 {
        key.weight() + val.weight()
    }
}

pub trait CacheItemWeight {
    fn weight(&self) -> u64;
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for TtlEntry<T> {
    fn weight(&self) -> u64 {
        self.value.weight() + std::mem::size_of::<Instant>() as u64
    }
}

impl<T: Clone + CacheItemWeight> CacheItemWeight for Option<T> {
    fn weight(&self) -> u64 {
        match self {
            Some(v) => v.weight(),
            None => std::mem::size_of::<usize>() as u64,
        }
    }
}

impl<T: CacheItemWeight> CacheItemWeight for Arc<T> {
    fn weight(&self) -> u64 {
        self.as_ref().weight()
    }
}

impl CacheItemWeight for u64 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u64>() as u64
    }
}

impl CacheItemWeight for String {
    fn weight(&self) -> u64 {
        self.len() as u64 + std::mem::size_of::<String>() as u64
    }
}

impl CacheItemWeight for u32 {
    fn weight(&self) -> u64 {
        std::mem::size_of::<u32>() as u64
    }
}

impl CacheItemWeight for Vec<IpAddr> {
    fn weight(&self) -> u64 {
        (self.len() * std::mem::size_of::<IpAddr>()) as u64
            + std::mem::size_of::<Vec<IpAddr>>() as u64
    }
}

impl CacheItemWeight for Vec<Ipv4Addr> {
    fn weight(&self) -> u64 {
        (self.len() * std::mem::size_of::<Ipv4Addr>()) as u64
            + std::mem::size_of::<Vec<Ipv4Addr>>() as u64
    }
}

impl CacheItemWeight for Vec<Ipv6Addr> {
    fn weight(&self) -> u64 {
        (self.len() * std::mem::size_of::<Ipv6Addr>()) as u64
            + std::mem::size_of::<Vec<Ipv6Addr>>() as u64
    }
}

impl CacheItemWeight for Vec<MX> {
    fn weight(&self) -> u64 {
        self.iter()
            .map(|mx| {
                mx.exchanges
                    .iter()
                    .map(|e| e.len() + std::mem::size_of::<MX>())
                    .sum::<usize>()
            })
            .sum::<usize>() as u64
            + std::mem::size_of::<Vec<MX>>() as u64
    }
}

impl CacheItemWeight for Vec<String> {
    fn weight(&self) -> u64 {
        self.iter().map(|s| s.len()).sum::<usize>() as u64
            + std::mem::size_of::<Vec<String>>() as u64
    }
}

impl CacheItemWeight for Txt {
    fn weight(&self) -> u64 {
        std::mem::size_of::<Txt>() as u64
    }
}

impl CacheItemWeight for IpAddr {
    fn weight(&self) -> u64 {
        std::mem::size_of::<IpAddr>() as u64
    }
}

impl CacheItemWeight for bool {
    fn weight(&self) -> u64 {
        std::mem::size_of::<bool>() as u64
    }
}

impl<T: Clone + CacheItemWeight> TtlEntry<T> {
    pub fn new(value: T, expires: Duration) -> Self {
        Self {
            value,
            expires: Instant::now() + expires,
        }
    }

    pub fn with_expiry(value: T, expires: Instant) -> Self {
        Self { value, expires }
    }
}

impl<K: Eq + Hash + CacheItemWeight, V: Clone + CacheItemWeight> ResolverCache<K, V>
    for CacheWithTtl<K, V>
{
    fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::get(self, key)
    }

    fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        CacheWithTtl::remove(self, key)
    }

    fn insert(&self, key: K, value: V, expires: Instant) {
        self.0.insert(key, TtlEntry::with_expiry(value, expires));
    }
}
