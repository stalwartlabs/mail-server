use ahash::AHashSet;
use utils::{codec::leb128::Leb128Vec, map::vec_map::VecMap};

use crate::Serialize;

use super::{IntoOperations, Operation};

#[derive(Default)]
pub struct ChangeLogBuilder {
    pub change_id: u64,
    pub changes: VecMap<u8, Changes>,
}

#[derive(Default)]
pub struct Changes {
    pub inserts: AHashSet<u64>,
    pub updates: AHashSet<u64>,
    pub deletes: AHashSet<u64>,
    pub child_updates: AHashSet<u64>,
}

impl ChangeLogBuilder {
    pub fn with_change_id(change_id: u64) -> ChangeLogBuilder {
        ChangeLogBuilder {
            change_id,
            changes: VecMap::default(),
        }
    }

    pub fn log_insert(&mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) {
        self.changes
            .get_mut_or_insert(collection.into())
            .inserts
            .insert(jmap_id.into());
    }

    pub fn log_update(&mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) {
        self.changes
            .get_mut_or_insert(collection.into())
            .updates
            .insert(jmap_id.into());
    }

    pub fn log_child_update(&mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) {
        self.changes
            .get_mut_or_insert(collection.into())
            .child_updates
            .insert(jmap_id.into());
    }

    pub fn log_delete(&mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) {
        self.changes
            .get_mut_or_insert(collection.into())
            .deletes
            .insert(jmap_id.into());
    }

    pub fn log_move(
        &mut self,
        collection: impl Into<u8>,
        old_jmap_id: impl Into<u64>,
        new_jmap_id: impl Into<u64>,
    ) {
        let change = self.changes.get_mut_or_insert(collection.into());
        change.deletes.insert(old_jmap_id.into());
        change.inserts.insert(new_jmap_id.into());
    }
}

impl IntoOperations for ChangeLogBuilder {
    fn build(self, batch: &mut super::BatchBuilder) -> crate::Result<()> {
        for (collection, changes) in self.changes {
            batch.ops.push(Operation::Log {
                change_id: self.change_id,
                collection,
                set: changes.serialize(),
            });
        }

        Ok(())
    }
}

impl Serialize for Changes {
    fn serialize(self) -> Vec<u8> {
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

        for list in [self.inserts, self.updates, self.child_updates, self.deletes] {
            for id in list {
                buf.push_leb128(id);
            }
        }
        buf
    }
}
