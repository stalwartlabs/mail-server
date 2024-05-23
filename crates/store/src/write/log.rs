/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use ahash::AHashSet;
use utils::{codec::leb128::Leb128Vec, map::vec_map::VecMap};

use crate::Serialize;

use super::{IntoOperations, MaybeDynamicValue, Operation, SerializeWithId};

#[derive(Default, Debug)]
pub struct ChangeLogBuilder {
    pub change_id: u64,
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
    pub fn new() -> ChangeLogBuilder {
        ChangeLogBuilder {
            change_id: u64::MAX,
            changes: VecMap::default(),
        }
    }

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

    pub fn with_log_insert(mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) -> Self {
        self.log_insert(collection, jmap_id);
        self
    }

    pub fn with_log_move(
        mut self,
        collection: impl Into<u8>,
        old_jmap_id: impl Into<u64>,
        new_jmap_id: impl Into<u64>,
    ) -> Self {
        self.log_move(collection, old_jmap_id, new_jmap_id);
        self
    }

    pub fn with_log_update(mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) -> Self {
        self.log_update(collection, jmap_id);
        self
    }

    pub fn with_log_delete(mut self, collection: impl Into<u8>, jmap_id: impl Into<u64>) -> Self {
        self.log_delete(collection, jmap_id);
        self
    }

    pub fn merge(&mut self, changes: ChangeLogBuilder) {
        for (collection, other) in changes.changes {
            let this = self.changes.get_mut_or_insert(collection);
            for id in other.deletes {
                if !this.inserts.remove(&id) {
                    this.deletes.insert(id);
                }
                this.updates.remove(&id);
                this.child_updates.remove(&id);
            }
            this.inserts.extend(other.inserts);
            this.updates.extend(other.updates);
            this.child_updates.extend(other.child_updates);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl IntoOperations for ChangeLogBuilder {
    fn build(self, batch: &mut super::BatchBuilder) {
        batch.with_change_id(self.change_id);
        for (collection, changes) in self.changes {
            batch.ops.push(Operation::Collection { collection });
            batch.ops.push(Operation::Log {
                set: changes.serialize().into(),
            });
        }
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

impl Serialize for &Changes {
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

impl From<Changes> for MaybeDynamicValue {
    fn from(changes: Changes) -> Self {
        MaybeDynamicValue::Static(changes.serialize())
    }
}

pub struct LogInsert();

impl SerializeWithId for LogInsert {
    fn serialize_with_id(&self, ids: &super::AssignedIds) -> crate::Result<Vec<u8>> {
        ids.last_document_id()
            .map(|id| Changes::insert([id]).serialize())
    }
}

impl From<LogInsert> for MaybeDynamicValue {
    fn from(value: LogInsert) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(value))
    }
}
