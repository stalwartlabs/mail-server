/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, fmt};

use serde::{de::DeserializeOwned, ser::SerializeMap, Deserialize, Serialize};

// A map implemented using vectors
// used for small datasets of less than 20 items
// and when deserializing from JSON

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VecMap<K: Eq + PartialEq, V> {
    pub k: Vec<K>,
    pub v: Vec<V>,
}

impl<K: Eq + PartialEq, V> Default for VecMap<K, V> {
    fn default() -> Self {
        VecMap {
            k: Vec::new(),
            v: Vec::new(),
        }
    }
}

impl<K: Eq + PartialEq, V> VecMap<K, V> {
    pub fn new() -> Self {
        Self {
            k: Vec::new(),
            v: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            k: Vec::with_capacity(capacity),
            v: Vec::with_capacity(capacity),
        }
    }

    #[inline(always)]
    pub fn set(&mut self, key: K, value: V) -> bool {
        if let Some(pos) = self.k.iter().position(|k| *k == key) {
            self.v[pos] = value;
            false
        } else {
            self.k.push(key);
            self.v.push(value);
            true
        }
    }

    #[inline(always)]
    pub fn append(&mut self, key: K, value: V) {
        self.k.push(key);
        self.v.push(value);
    }

    #[inline(always)]
    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + PartialEq<Q>,
    {
        self.k.iter().position(|k| k == key).map(|pos| &self.v[pos])
    }

    #[inline(always)]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.k
            .iter_mut()
            .position(|k| k == key)
            .map(|pos| &mut self.v[pos])
    }

    #[inline(always)]
    pub fn contains_key(&self, key: &K) -> bool {
        self.k.contains(key)
    }

    #[inline(always)]
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.k.iter().position(|k| k == key).map(|pos| {
            self.k.swap_remove(pos);
            self.v.swap_remove(pos)
        })
    }

    #[inline(always)]
    pub fn remove_entry(&mut self, key: &K) -> Option<(K, V)> {
        self.k
            .iter()
            .position(|k| k == key)
            .map(|pos| (self.k.swap_remove(pos), self.v.swap_remove(pos)))
    }

    #[inline(always)]
    pub fn swap_remove(&mut self, index: usize) -> V {
        self.k.swap_remove(index);
        self.v.swap_remove(index)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.k.is_empty()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.k.len()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.k.clear();
        self.v.clear();
    }

    #[inline(always)]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.k.iter().zip(self.v.iter())
    }

    #[inline(always)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&mut K, &mut V)> {
        self.k.iter_mut().zip(self.v.iter_mut())
    }

    #[inline(always)]
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.k.iter()
    }

    #[inline(always)]
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.v.iter()
    }

    #[inline(always)]
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.v.iter_mut()
    }

    pub fn get_mut_or_insert_with(&mut self, key: K, fnc: impl FnOnce() -> V) -> &mut V {
        if let Some(pos) = self.k.iter().position(|k| k == &key) {
            &mut self.v[pos]
        } else {
            self.k.push(key);
            self.v.push(fnc());
            self.v.last_mut().unwrap()
        }
    }
}

impl<K: Eq + PartialEq, V: Default> VecMap<K, V> {
    pub fn get_mut_or_insert(&mut self, key: K) -> &mut V {
        if let Some(pos) = self.k.iter().position(|k| k == &key) {
            &mut self.v[pos]
        } else {
            self.k.push(key);
            self.v.push(V::default());
            self.v.last_mut().unwrap()
        }
    }
}

impl<K: Eq + PartialEq, V> IntoIterator for VecMap<K, V> {
    type Item = (K, V);

    type IntoIter = std::iter::Zip<std::vec::IntoIter<K>, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.k.into_iter().zip(self.v)
    }
}

impl<'x, K: Eq + PartialEq, V> IntoIterator for &'x VecMap<K, V> {
    type Item = (&'x K, &'x V);

    type IntoIter = std::iter::Zip<std::slice::Iter<'x, K>, std::slice::Iter<'x, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.k.iter().zip(self.v.iter())
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
