/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Batch, BatchBuilder, BitmapClass, ChangedCollection, IntoOperations, Operation, TagValue,
    ValueClass, ValueOp, assert::ToAssertValue,
};
use crate::{SerializeInfallible, U32_LEN};
use std::sync::{
    LazyLock,
    atomic::{AtomicU64, Ordering},
};
use utils::{
    map::{bitmap::ShortId, vec_map::VecMap},
    snowflake::SnowflakeIdGenerator,
};

static CHANGE_SEQ: AtomicU64 = AtomicU64::new(0);
static NODE_MUM: LazyLock<u16> = LazyLock::new(|| CHANGE_SEQ.swap(0, Ordering::Relaxed) as u16);

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(32),
            current_change_id: None,
            current_account_id: None,
            current_collection: None,
            current_document_id: None,
            changes: Default::default(),
            changed_collections: Default::default(),
            batch_size: 0,
            batch_ops: 0,
            has_assertions: false,
            commit_points: Vec::new(),
        }
    }

    pub fn init_id_generator(node_number: u16) {
        CHANGE_SEQ.store(node_number as u64, Ordering::Relaxed);
    }

    fn generate_change_id(&mut self) -> u64 {
        let change_id = SnowflakeIdGenerator::from_params(
            CHANGE_SEQ.fetch_add(1, Ordering::Relaxed),
            *NODE_MUM,
        );
        self.current_change_id = Some(change_id);
        change_id
    }

    pub fn with_account_id(&mut self, account_id: u32) -> &mut Self {
        if self
            .current_account_id
            .is_none_or(|current_account_id| current_account_id != account_id)
        {
            self.current_account_id = account_id.into();
            self.ops.push(Operation::AccountId { account_id });
        }
        self
    }

    pub fn with_collection(&mut self, collection: impl Into<u8>) -> &mut Self {
        let collection = collection.into();
        let collection_ = Some(collection);
        if collection_ != self.current_collection {
            self.current_collection = collection_;
            self.ops.push(Operation::Collection { collection });
        }
        self
    }

    pub fn create_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: true,
        });
        self.current_document_id = Some(document_id);
        self.batch_size += U32_LEN * 3;
        self.batch_ops += 1;
        self.has_assertions = false;
        self
    }

    pub fn update_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.current_document_id = Some(document_id);
        self.has_assertions = false;
        self
    }

    pub fn delete_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: false,
        });
        self.current_document_id = Some(document_id);
        self.batch_size += U32_LEN * 3;
        self.batch_ops += 1;
        self.has_assertions = false;
        self
    }

    pub fn assert_value(
        &mut self,
        class: impl Into<ValueClass>,
        value: impl ToAssertValue,
    ) -> &mut Self {
        self.ops.push(Operation::AssertValue {
            class: class.into(),
            assert_value: value.to_assert_value(),
        });
        self.batch_ops += 1;
        self.has_assertions = true;
        self
    }

    pub fn index(&mut self, field: impl Into<u8>, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: true,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn unindex(&mut self, field: impl Into<u8>, value: impl Into<Vec<u8>>) -> &mut Self {
        let field = field.into();
        let value = value.into();
        let value_len = value.len();

        self.ops.push(Operation::Index {
            field,
            key: value,
            set: false,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn tag(&mut self, field: impl Into<u8>, value: impl Into<TagValue>) -> &mut Self {
        let value = value.into();
        let value_len = value.serialized_size();
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field: field.into(),
                value,
            },
            set: true,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn untag(&mut self, field: impl Into<u8>, value: impl Into<TagValue>) -> &mut Self {
        let value = value.into();
        let value_len = value.serialized_size();
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field: field.into(),
                value,
            },
            set: false,
        });
        self.batch_size += (U32_LEN * 3) + value_len;
        self.batch_ops += 1;
        self
    }

    pub fn add(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size() + std::mem::size_of::<i64>();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AtomicAdd(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn add_and_get(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size() + (std::mem::size_of::<i64>() * 2);
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::AddAndGet(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn set(&mut self, class: impl Into<ValueClass>, value: impl Into<Vec<u8>>) -> &mut Self {
        let class = class.into();
        let value = value.into();
        self.batch_size += class.serialized_size() + value.len();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Set(value),
        });
        self.batch_ops += 1;
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass>) -> &mut Self {
        let class = class.into();
        self.batch_size += class.serialized_size();
        self.ops.push(Operation::Value {
            class,
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_grant(&mut self, grant_account_id: u32, op: Vec<u8>) -> &mut Self {
        self.batch_size += (U32_LEN * 3) + op.len();
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Set(op),
        });
        self.batch_ops += 1;
        self
    }

    pub fn acl_revoke(&mut self, grant_account_id: u32) -> &mut Self {
        self.batch_size += U32_LEN * 3;
        self.ops.push(Operation::Value {
            class: ValueClass::Acl(grant_account_id),
            op: ValueOp::Clear,
        });
        self.batch_ops += 1;
        self
    }

    pub fn log_item_insert(&mut self, collection: impl Into<u8>, prefix: Option<u32>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_insert(
                collection.into(),
                prefix,
                document_id,
            );
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_item_update(&mut self, collection: impl Into<u8>, prefix: Option<u32>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_update(
                collection.into(),
                prefix,
                document_id,
            );
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_item_delete(&mut self, collection: impl Into<u8>, prefix: Option<u32>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes.get_mut_or_insert(account_id).log_item_delete(
                collection.into(),
                prefix,
                document_id,
            );
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_container_insert(&mut self, collection: impl Into<u8>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_insert(collection.into(), document_id);
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_container_update(&mut self, collection: impl Into<u8>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_update(collection.into(), document_id);
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_container_delete(&mut self, collection: impl Into<u8>) -> &mut Self {
        if let (Some(account_id), Some(document_id)) =
            (self.current_account_id, self.current_document_id)
        {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_delete(collection.into(), document_id);
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    pub fn log_container_property_change(
        &mut self,
        collection: impl Into<u8>,
        document_id: u32,
    ) -> &mut Self {
        if let Some(account_id) = self.current_account_id {
            self.changes
                .get_mut_or_insert(account_id)
                .log_container_property_update(collection.into(), document_id);
        }
        if self.current_change_id.is_none() {
            self.generate_change_id();
            self.batch_ops += 1;
        }
        self
    }

    fn serialize_changes(&mut self) {
        if let Some(change_id) = self.current_change_id.take() {
            if !self.changes.is_empty() {
                for (account_id, changelog) in std::mem::take(&mut self.changes) {
                    self.with_account_id(account_id);

                    for (collection, changes) in changelog.into_iterator() {
                        let cc = self.changed_collections.get_mut_or_insert(account_id);
                        cc.change_id = change_id;
                        if changes.has_container_changes() {
                            cc.changed_containers.insert(ShortId(collection));
                        }
                        if changes.has_item_changes() {
                            cc.changed_items.insert(ShortId(collection));
                        }

                        self.ops.push(Operation::Log {
                            change_id,
                            collection,
                            set: changes.serialize(),
                        });
                    }
                }
            }
        }
    }

    pub fn commit_point(&mut self) -> &mut Self {
        if self.batch_size > 5_000_000 || self.batch_ops > 1000 {
            self.serialize_changes();
            self.commit_points.push(self.ops.len());
            self.batch_ops = 0;
            self.batch_size = 0;
            if let Some(account_id) = self.current_account_id {
                self.ops.push(Operation::AccountId { account_id });
            }
            if let Some(collection) = self.current_collection {
                self.ops.push(Operation::Collection { collection });
            }
        }
        self
    }

    pub fn any_op(&mut self, op: Operation) -> &mut Self {
        self.ops.push(op);
        self.batch_ops += 1;
        self
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> trc::Result<&mut Self> {
        value.build(self)?;
        Ok(self)
    }

    pub fn last_account_id(&self) -> Option<u32> {
        self.current_account_id
    }

    pub fn change_id(&mut self) -> u64 {
        self.current_change_id
            .unwrap_or_else(|| self.generate_change_id())
    }

    pub fn last_change_id(&self) -> Option<u64> {
        self.current_change_id
    }

    pub fn build(&mut self) -> impl Iterator<Item = Batch<'_>> {
        self.serialize_changes();
        self.build_batches()
    }

    fn build_batches(&self) -> impl Iterator<Item = Batch<'_>> {
        let mut offset_start = 0;
        self.commit_points
            .iter()
            .copied()
            .chain([self.ops.len()])
            .map(move |point| {
                let batch = Batch {
                    ops: &self.ops[offset_start..point],
                };
                offset_start = point;
                batch
            })
    }

    pub fn build_all(&mut self) -> Batch<'_> {
        self.serialize_changes();
        Batch {
            ops: self.ops.as_slice(),
        }
    }

    pub fn changes(self) -> Option<VecMap<u32, ChangedCollection>> {
        if self.has_changes() {
            Some(self.changed_collections)
        } else {
            None
        }
    }

    pub fn has_changes(&self) -> bool {
        !self.changed_collections.is_empty()
    }

    pub fn ops(&self) -> &[Operation] {
        self.ops.as_slice()
    }

    pub fn len(&self) -> usize {
        self.batch_size
    }

    pub fn is_empty(&self) -> bool {
        self.batch_ops == 0
    }
}

impl Batch<'_> {
    pub fn is_atomic(&self) -> bool {
        !self.ops.iter().any(|op| {
            matches!(
                op,
                Operation::AssertValue { .. }
                    | Operation::Value {
                        op: ValueOp::AddAndGet(_),
                        ..
                    }
            )
        })
    }

    pub fn first_account_id(&self) -> Option<u32> {
        self.ops.iter().find_map(|op| match op {
            Operation::AccountId { account_id } => Some(*account_id),
            _ => None,
        })
    }
}

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
