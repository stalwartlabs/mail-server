/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use utils::{codec::leb128::Leb128Vec, map::vec_map::VecMap};

use crate::SerializeInfallible;

#[derive(Default, Debug)]
pub(crate) struct ChangeLogBuilder {
    pub changes: VecMap<u8, Changes>,
}

#[derive(Default, Debug)]
pub struct Changes {
    pub inserts: AHashSet<u64>,
    pub updates: AHashSet<u64>,
    pub deletes: AHashSet<u64>,
    pub child_updates: AHashSet<u64>,
}

impl ChangeLogBuilder {
    pub fn serialize(self) -> impl Iterator<Item = (u8, Vec<u8>)> {
        self.changes
            .into_iter()
            .map(|(collection, changes)| (collection, changes.serialize()))
    }

    pub fn log_insert(&mut self, collection: impl Into<u8>, prefix: Option<u32>, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection.into())
            .inserts
            .insert(build_id(prefix, document_id));
    }

    pub fn log_update(&mut self, collection: impl Into<u8>, prefix: Option<u32>, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection.into())
            .updates
            .insert(build_id(prefix, document_id));
    }

    pub fn log_delete(&mut self, collection: impl Into<u8>, prefix: Option<u32>, document_id: u32) {
        let changes = self.changes.get_mut_or_insert(collection.into());
        let id = build_id(prefix, document_id);
        changes.updates.remove(&id);
        changes.deletes.insert(id);
    }

    pub fn log_child_update(
        &mut self,
        collection: impl Into<u8>,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        self.changes
            .get_mut_or_insert(collection.into())
            .child_updates
            .insert(build_id(prefix, document_id));
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[inline(always)]
fn build_id(prefix: Option<u32>, document_id: u32) -> u64 {
    if let Some(prefix) = prefix {
        ((prefix as u64) << 32) | document_id as u64
    } else {
        document_id as u64
    }
}

impl Changes {
    pub fn insert<T, I>(id: T) -> Self
    where
        T: IntoIterator<Item = I>,
        I: Into<u64>,
    {
        Changes {
            inserts: id.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn update<T, I>(id: T) -> Self
    where
        T: IntoIterator<Item = I>,
        I: Into<u64>,
    {
        Changes {
            updates: id.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn child_update<T, I>(id: T) -> Self
    where
        T: IntoIterator<Item = I>,
        I: Into<u64>,
    {
        Changes {
            child_updates: id.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn delete<T, I>(id: T) -> Self
    where
        T: IntoIterator<Item = I>,
        I: Into<u64>,
    {
        Changes {
            deletes: id.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }
}

impl SerializeInfallible for Changes {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + (self.inserts.len()
                + self.updates.len()
                + self.child_updates.len()
                + self.deletes.len()
                + 4)
                * std::mem::size_of::<usize>(),
        );

        buf.push_leb128(self.inserts.len());
        buf.push_leb128(self.updates.len());
        buf.push_leb128(self.child_updates.len());
        buf.push_leb128(self.deletes.len());

        for list in [
            &self.inserts,
            &self.updates,
            &self.child_updates,
            &self.deletes,
        ] {
            for id in list {
                buf.push_leb128(*id);
            }
        }
        buf
    }
}
