/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, cmp::Ordering, fmt, hash::Hash};

use rkyv::Archive;
use serde::{Deserialize, Serialize, de::DeserializeOwned, ser::SerializeMap};

// A map implemented using vectors
// used for small datasets of less than 20 items
// and when deserializing from JSON

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct VecMap<K: Eq + PartialEq, V> {
    inner: Vec<KeyValue<K, V>>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyValue<K: Eq + PartialEq, V> {
    key: K,
    value: V,
}

impl<K: Eq + PartialEq, V> Default for VecMap<K, V> {
    fn default() -> Self {
        VecMap { inner: Vec::new() }
    }
}

impl<K: Eq + PartialEq, V> VecMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub fn set(&mut self, key: K, value: V) -> bool {
        if let Some(kv) = self.inner.iter_mut().find(|kv| kv.key == key) {
            kv.value = value;
            false
        } else {
            self.inner.push(KeyValue { key, value });
            true
        }
    }

    #[inline(always)]
    pub fn append(&mut self, key: K, value: V) {
        self.inner.push(KeyValue { key, value });
    }

    #[inline(always)]
    pub fn with_append(mut self, key: K, value: V) -> Self {
        self.append(key, value);
        self
    }

    #[inline(always)]
    pub fn insert(&mut self, idx: usize, key: K, value: V) {
        self.inner.insert(idx, KeyValue { key, value });
    }

    #[inline(always)]
    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + PartialEq<Q>,
    {
        self.inner.iter().find_map(|kv| {
            if &kv.key == key {
                Some(&kv.value)
            } else {
                None
            }
        })
    }

    #[inline(always)]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.iter_mut().find_map(|kv| {
            if &kv.key == key {
                Some(&mut kv.value)
            } else {
                None
            }
        })
    }

    #[inline(always)]
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.iter().any(|kv| kv.key == *key)
    }

    #[inline(always)]
    pub fn remove<Q: ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q> + PartialEq<Q>,
    {
        self.inner
            .iter()
            .position(|kv| kv.key == *key)
            .map(|pos| self.inner.remove(pos).value)
    }

    #[inline(always)]
    pub fn remove_all(&mut self, key: &K) {
        self.inner.retain(|kv| kv.key != *key);
    }

    #[inline(always)]
    pub fn remove_entry(&mut self, key: &K) -> Option<(K, V)> {
        self.inner.iter().position(|k| &k.key == key).map(|pos| {
            let kv = self.inner.remove(pos);
            (kv.key, kv.value)
        })
    }

    #[inline(always)]
    pub fn swap_remove(&mut self, index: usize) -> V {
        self.inner.swap_remove(index).value
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline(always)]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.inner.iter().map(|kv| (&kv.key, &kv.value))
    }

    #[inline(always)]
    pub fn iter_by_key<'x, 'y: 'x>(&'x self, key: &'y K) -> impl Iterator<Item = &'x V> + 'x {
        self.inner.iter().filter_map(move |kv| {
            if &kv.key == key {
                Some(&kv.value)
            } else {
                None
            }
        })
    }

    #[inline(always)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&mut K, &mut V)> {
        self.inner.iter_mut().map(|kv| (&mut kv.key, &mut kv.value))
    }

    #[inline(always)]
    pub fn iter_mut_by_key<'x, 'y: 'x>(
        &'x mut self,
        key: &'y K,
    ) -> impl Iterator<Item = &'x mut V> + 'x {
        self.inner.iter_mut().filter_map(move |kv| {
            if &kv.key == key {
                Some(&mut kv.value)
            } else {
                None
            }
        })
    }

    #[inline(always)]
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.inner.iter().map(|kv| &kv.key)
    }

    #[inline(always)]
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.inner.iter().map(|kv| &kv.value)
    }

    #[inline(always)]
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.inner.iter_mut().map(|kv| &mut kv.value)
    }

    pub fn get_mut_or_insert_with(&mut self, key: K, fnc: impl FnOnce() -> V) -> &mut V {
        if let Some(pos) = self.inner.iter().position(|kv| kv.key == key) {
            &mut self.inner[pos].value
        } else {
            self.inner.push(KeyValue { key, value: fnc() });
            &mut self.inner.last_mut().unwrap().value
        }
    }

    pub fn with_key_value(mut self, key: K, value: V) -> Self {
        self.append(key, value);
        self
    }

    pub fn sort_unstable(&mut self)
    where
        K: Ord,
        V: Ord,
    {
        self.inner.sort_unstable_by(|a, b| match a.key.cmp(&b.key) {
            Ordering::Equal => a.value.cmp(&b.value),
            cmp => cmp,
        });
    }
}

impl<K: Eq + PartialEq, V: Default> VecMap<K, V> {
    pub fn get_mut_or_insert(&mut self, key: K) -> &mut V {
        if let Some(pos) = self.inner.iter().position(|kv| kv.key == key) {
            &mut self.inner[pos].value
        } else {
            self.inner.push(KeyValue {
                key,
                value: V::default(),
            });
            &mut self.inner.last_mut().unwrap().value
        }
    }
}

impl<K: Archive + Eq + PartialEq, V: Archive> ArchivedVecMap<K, V> {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline(always)]
    pub fn iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &<K as rkyv::Archive>::Archived,
            &<V as rkyv::Archive>::Archived,
        ),
    > {
        self.inner.iter().map(|kv| (&kv.key, &kv.value))
    }
}

impl<K: Eq + PartialEq, V> IntoIterator for VecMap<K, V> {
    type Item = (K, V);

    type IntoIter =
        std::iter::Map<std::vec::IntoIter<KeyValue<K, V>>, fn(KeyValue<K, V>) -> (K, V)>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter().map(|kv| (kv.key, kv.value))
    }
}

impl<'x, K: Eq + PartialEq, V> IntoIterator for &'x VecMap<K, V> {
    type Item = (&'x K, &'x V);

    type IntoIter = std::iter::Map<
        std::slice::Iter<'x, KeyValue<K, V>>,
        fn(&'x KeyValue<K, V>) -> (&'x K, &'x V),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter().map(|kv| (&kv.key, &kv.value))
    }
}

impl<K, V> Hash for VecMap<K, V>
where
    K: Eq + PartialEq + Hash,
    V: Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<K: Eq + PartialEq, V> FromIterator<(K, V)> for VecMap<K, V> {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (K, V)>,
    {
        let mut map = VecMap::new();
        for (k, v) in iter {
            map.append(k, v);
        }
        map
    }
}

struct VecMapVisitor<K, V> {
    phantom: std::marker::PhantomData<(K, V)>,
}

impl<'de, K: Eq + PartialEq + DeserializeOwned, V: DeserializeOwned> serde::de::Visitor<'de>
    for VecMapVisitor<K, V>
{
    type Value = VecMap<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        // Duplicates are not checked during deserialization
        let mut vec_map = VecMap::new();
        while let Some(key) = map.next_key::<K>()? {
            vec_map.append(key, map.next_value()?);
        }
        Ok(vec_map)
    }
}

impl<'de, K: Eq + PartialEq + DeserializeOwned, V: DeserializeOwned> Deserialize<'de>
    for VecMap<K, V>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(VecMapVisitor {
            phantom: std::marker::PhantomData,
        })
    }
}

impl<K: Eq + PartialEq + Serialize, V: Serialize> Serialize for VecMap<K, V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(self.len().into())?;

        for (key, value) in self {
            map.serialize_entry(key, value)?
        }

        map.end()
    }
}
