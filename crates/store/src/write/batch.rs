/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    assert::ToAssertValue, Batch, BatchBuilder, BitmapClass, HasFlag, IntoOperations,
    MaybeDynamicId, MaybeDynamicValue, Operation, Serialize, TagValue, ToBitmaps, ValueClass,
    ValueOp, F_BITMAP, F_CLEAR, F_INDEX, F_VALUE,
};

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(16),
        }
    }

    pub fn with_change_id(&mut self, change_id: u64) -> &mut Self {
        self.ops.push(Operation::ChangeId { change_id });
        self
    }

    pub fn with_account_id(&mut self, account_id: u32) -> &mut Self {
        self.ops.push(Operation::AccountId { account_id });
        self
    }

    pub fn with_collection(&mut self, collection: impl Into<u8>) -> &mut Self {
        self.ops.push(Operation::Collection {
            collection: collection.into(),
        });
        self
    }

    pub fn create_document(&mut self) -> &mut Self {
        self.ops.push(Operation::DocumentId {
            document_id: u32::MAX,
        });

        // Add document id
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: true,
        });

        self
    }

    pub fn create_document_with_id(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });

        // Add document id
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: true,
        });

        self
    }

    pub fn update_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self
    }

    pub fn delete_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: false,
        });
        self
    }

    pub fn assert_value(
        &mut self,
        class: impl Into<ValueClass<MaybeDynamicId>>,
        value: impl ToAssertValue,
    ) -> &mut Self {
        self.ops.push(Operation::AssertValue {
            class: class.into(),
            assert_value: value.to_assert_value(),
        });
        self
    }

    pub fn value(
        &mut self,
        field: impl Into<u8>,
        value: impl Serialize + ToBitmaps,
        options: u32,
    ) -> &mut Self {
        let field = field.into();
        let is_set = !options.has_flag(F_CLEAR);

        if options.has_flag(F_BITMAP) {
            value.to_bitmaps(&mut self.ops, field, is_set);
        }

        let value = value.serialize();

        if options.has_flag(F_INDEX) {
            self.ops.push(Operation::Index {
                field,
                key: value.clone(),
                set: is_set,
            });
        }

        if options.has_flag(F_VALUE) {
            self.ops.push(Operation::Value {
                class: ValueClass::Property(field),
                op: if is_set {
                    ValueOp::Set(value.into())
                } else {
                    ValueOp::Clear
                },
            });
        }

        self
    }

    pub fn tag(
        &mut self,
        field: impl Into<u8>,
        value: impl Into<TagValue<MaybeDynamicId>>,
        options: u32,
    ) -> &mut Self {
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::Tag {
                field: field.into(),
                value: value.into(),
            },
            set: !options.has_flag(F_CLEAR),
        });
        self
    }

    pub fn add(&mut self, class: impl Into<ValueClass<MaybeDynamicId>>, value: i64) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::AtomicAdd(value),
        });
        self
    }

    pub fn add_and_get(
        &mut self,
        class: impl Into<ValueClass<MaybeDynamicId>>,
        value: i64,
    ) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::AddAndGet(value),
        });
        self
    }

    pub fn set(
        &mut self,
        class: impl Into<ValueClass<MaybeDynamicId>>,
        value: impl Into<MaybeDynamicValue>,
    ) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::Set(value.into()),
        });
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass<MaybeDynamicId>>) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::Clear,
        });
        self
    }

    pub fn log(&mut self, value: impl Into<MaybeDynamicValue>) -> &mut Self {
        self.ops.push(Operation::Log { set: value.into() });
        self
    }

    pub fn custom(&mut self, value: impl IntoOperations) -> &mut Self {
        value.build(self);
        self
    }

    pub fn build(self) -> Batch {
        Batch { ops: self.ops }
    }

    pub fn build_batch(&mut self) -> Batch {
        Batch {
            ops: std::mem::take(&mut self.ops),
        }
    }

    pub fn last_account_id(&self) -> Option<u32> {
        self.ops.iter().rev().find_map(|op| match op {
            Operation::AccountId { account_id } => Some(*account_id),
            _ => None,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
            || !self.ops.iter().any(|op| {
                !matches!(
                    op,
                    Operation::AccountId { .. }
                        | Operation::Collection { .. }
                        | Operation::DocumentId { .. }
                        | Operation::AssertValue { .. }
                )
            })
    }
}

impl Batch {
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
