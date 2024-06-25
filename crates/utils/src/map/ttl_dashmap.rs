/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, hash::Hash, time::Instant};

use dashmap::DashMap;

pub type TtlDashMap<K, V> = DashMap<K, LruItem<V>, ahash::RandomState>;

#[derive(Debug, Clone)]
pub struct LruItem<V> {
    item: V,
    valid_until: Instant,
}

pub trait TtlMap<K, V>: Sized {
    fn with_capacity(capacity: usize, shard_amount: usize) -> Self;
    fn get_with_ttl<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    fn insert_with_ttl(&self, name: K, value: V, valid_until: Instant) -> V;
    fn cleanup(&self);
}

impl<K: Hash + Eq, V: Clone> TtlMap<K, V> for TtlDashMap<K, V> {
    fn with_capacity(capacity: usize, shard_amount: usize) -> Self {
        DashMap::with_capacity_and_hasher_and_shard_amount(
            capacity,
            ahash::RandomState::new(),
            shard_amount,
        )
    }

    fn get_with_ttl<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.get(name) {
            Some(entry) if entry.valid_until >= Instant::now() => entry.item.clone().into(),
            _ => None,
        }
    }

    fn insert_with_ttl(&self, name: K, item: V, valid_until: Instant) -> V {
        self.insert(
            name,
            LruItem {
                item: item.clone(),
                valid_until,
            },
        );
        item
    }

    fn cleanup(&self) {
        self.retain(|_, entry| entry.valid_until >= Instant::now());
    }
}
