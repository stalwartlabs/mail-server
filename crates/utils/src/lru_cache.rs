/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
