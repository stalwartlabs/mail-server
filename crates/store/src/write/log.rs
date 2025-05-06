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
    pub item_inserts: AHashSet<u64>,
    pub item_updates: AHashSet<u64>,
    pub item_deletes: AHashSet<u64>,

    pub container_inserts: AHashSet<u32>,
    pub container_updates: AHashSet<u32>,
    pub container_deletes: AHashSet<u32>,
    pub container_property_changes: AHashSet<u32>,
}

impl ChangeLogBuilder {
    pub fn into_iterator(self) -> impl Iterator<Item = (u8, Changes)> {
        self.changes.into_iter()
    }

    pub fn log_container_insert(&mut self, collection: impl Into<u8>, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection.into())
            .container_inserts
            .insert(document_id);
    }

    pub fn log_item_insert(
        &mut self,
        collection: impl Into<u8>,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        self.changes
            .get_mut_or_insert(collection.into())
            .item_inserts
            .insert(build_id(prefix, document_id));
    }

    pub fn log_container_update(&mut self, collection: impl Into<u8>, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection.into())
            .container_updates
            .insert(document_id);
    }

    pub fn log_container_property_update(&mut self, collection: impl Into<u8>, document_id: u32) {
        self.changes
            .get_mut_or_insert(collection.into())
            .container_property_changes
            .insert(document_id);
    }

    pub fn log_item_update(
        &mut self,
        collection: impl Into<u8>,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        self.changes
            .get_mut_or_insert(collection.into())
            .item_updates
            .insert(build_id(prefix, document_id));
    }

    pub fn log_container_delete(&mut self, collection: impl Into<u8>, document_id: u32) {
        let changes = self.changes.get_mut_or_insert(collection.into());
        let id = document_id;
        changes.container_updates.remove(&id);
        changes.container_property_changes.remove(&id);
        changes.container_deletes.insert(id);
    }

    pub fn log_item_delete(
        &mut self,
        collection: impl Into<u8>,
        prefix: Option<u32>,
        document_id: u32,
    ) {
        let changes = self.changes.get_mut_or_insert(collection.into());
        let id = build_id(prefix, document_id);
        changes.item_updates.remove(&id);
        changes.item_deletes.insert(id);
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
    pub fn has_container_changes(&self) -> bool {
        !self.container_inserts.is_empty()
            || !self.container_updates.is_empty()
            || !self.container_property_changes.is_empty()
            || !self.container_deletes.is_empty()
    }

    pub fn has_item_changes(&self) -> bool {
        !self.item_inserts.is_empty()
            || !self.item_updates.is_empty()
            || !self.item_deletes.is_empty()
    }
}

impl SerializeInfallible for Changes {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + (self.item_inserts.len()
                + self.item_updates.len()
                + self.item_deletes.len()
                + self.container_inserts.len()
                + self.container_updates.len()
                + self.container_property_changes.len()
                + self.container_deletes.len()
                + 4)
                * std::mem::size_of::<usize>(),
        );

        buf.push_leb128(self.container_inserts.len());
        buf.push_leb128(self.container_updates.len());
        buf.push_leb128(self.container_property_changes.len());
        buf.push_leb128(self.container_deletes.len());
        buf.push_leb128(self.item_inserts.len());
        buf.push_leb128(self.item_updates.len());
        buf.push_leb128(self.item_deletes.len());

        for list in [
            &self.container_inserts,
            &self.container_updates,
            &self.container_property_changes,
            &self.container_deletes,
        ] {
            for id in list {
                buf.push_leb128(*id);
            }
        }
        for list in [&self.item_inserts, &self.item_updates, &self.item_deletes] {
            for id in list {
                buf.push_leb128(*id);
            }
        }

        buf
    }
}
