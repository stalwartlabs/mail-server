/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, hash::Hash};

use parking_lot::Mutex;

pub type LruCache<K, V> = Mutex<lru_cache::LruCache<K, V, ahash::RandomState>>;

pub trait LruCached<K, V>: Sized {
    fn with_capacity(capacity: usize) -> Self;
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized;
    fn insert(&self, name: K, value: V) -> Option<V>;
}

impl<K: Hash + Eq, V: Clone> LruCached<K, V> for LruCache<K, V> {
    fn with_capacity(capacity: usize) -> Self {
        Mutex::new(lru_cache::LruCache::with_hasher(
            capacity,
            ahash::RandomState::new(),
        ))
    }

    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.lock().get_mut(name).map(|entry| entry.clone())
    }

    fn insert(&self, name: K, item: V) -> Option<V> {
        self.lock().insert(name, item)
    }
}
