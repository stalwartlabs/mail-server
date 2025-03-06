/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Borrow, rc::Rc};

use ahash::AHashMap;

#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
struct StringRef(Rc<String>);

#[derive(Debug, Default)]
pub struct IdBimap {
    id_to_uri: AHashMap<u32, Rc<String>>,
    uri_to_id: AHashMap<StringRef, u32>,
}

impl IdBimap {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            id_to_uri: AHashMap::with_capacity(capacity),
            uri_to_id: AHashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, id: u32, uri: impl Into<String>) {
        let uri = Rc::new(uri.into());
        self.id_to_uri.insert(id, uri.clone());
        self.uri_to_id.insert(StringRef(uri), id);
    }

    pub fn by_name(&self, uri: &str) -> Option<u32> {
        self.uri_to_id.get(uri).copied()
    }

    pub fn by_id(&self, id: u32) -> Option<&str> {
        self.id_to_uri.get(&id).map(|x| x.as_str())
    }
}

// SAFETY: Safe because Rc<> are never returned from the struct
unsafe impl Send for IdBimap {}
unsafe impl Sync for IdBimap {}

impl Borrow<str> for StringRef {
    fn borrow(&self) -> &str {
        &self.0
    }
}
