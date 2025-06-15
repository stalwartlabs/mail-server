/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, hash::Hash, rc::Rc};

use ahash::AHashMap;

#[derive(Debug)]
#[repr(transparent)]
struct StringRef<T: IdBimapItem>(Rc<T>);

#[derive(Debug)]
#[repr(transparent)]
struct IdRef<T: IdBimapItem>(Rc<T>);

#[derive(Debug, Default)]
pub struct IdBimap<T: IdBimapItem> {
    id_to_name: AHashMap<IdRef<T>, Rc<T>>,
    name_to_id: AHashMap<StringRef<T>, Rc<T>>,
}

impl<T: IdBimapItem> IdBimap<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            id_to_name: AHashMap::with_capacity(capacity),
            name_to_id: AHashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, item: T) {
        let item = Rc::new(item);
        self.id_to_name.insert(IdRef(item.clone()), item.clone());
        self.name_to_id.insert(StringRef(item.clone()), item);
    }

    pub fn by_name(&self, name: &str) -> Option<&T> {
        self.name_to_id.get(name).map(|v| v.as_ref())
    }

    pub fn by_id(&self, id: u32) -> Option<&T> {
        self.id_to_name.get(&id).map(|v| v.as_ref())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.name_to_id.values().map(|v| v.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.name_to_id.is_empty()
    }
}

// SAFETY: Safe because Rc<> are never returned from the struct
unsafe impl<T: IdBimapItem> Send for IdBimap<T> {}
unsafe impl<T: IdBimapItem> Sync for IdBimap<T> {}

pub trait IdBimapItem: std::fmt::Debug {
    fn id(&self) -> &u32;
    fn name(&self) -> &str;
}

impl<T: IdBimapItem> Borrow<str> for StringRef<T> {
    fn borrow(&self) -> &str {
        self.0.name()
    }
}

impl<T: IdBimapItem> Borrow<u32> for IdRef<T> {
    fn borrow(&self) -> &u32 {
        self.0.id()
    }
}

impl<T: IdBimapItem> PartialEq for StringRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl<T: IdBimapItem> Eq for StringRef<T> {}

impl<T: IdBimapItem> PartialEq for IdRef<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}

impl<T: IdBimapItem> Eq for IdRef<T> {}

impl<T: IdBimapItem> Hash for StringRef<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name().hash(state)
    }
}

impl<T: IdBimapItem> Hash for IdRef<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.id().hash(state)
    }
}
