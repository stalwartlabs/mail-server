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

use crate::BlobHash;

use super::{
    assert::ToAssertValue, Batch, BatchBuilder, BitmapClass, BlobOp, HasFlag, IntoOperations,
    Operation, Serialize, TagValue, ToBitmaps, ValueClass, ValueOp, F_BITMAP, F_CLEAR, F_INDEX,
    F_VALUE,
};

impl BatchBuilder {
    pub fn new() -> Self {
        Self {
            ops: Vec::with_capacity(16),
        }
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

    pub fn create_document(&mut self, document_id: u32) -> &mut Self {
        self.ops.push(Operation::DocumentId { document_id });

        // Add document id
        self.ops.push(Operation::Bitmap {
            class: BitmapClass::DocumentIds,
            set: true,
        });

        // Remove reserved id
        self.ops.push(Operation::Value {
            class: ValueClass::ReservedId,
            op: ValueOp::Clear,
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
        class: impl Into<ValueClass>,
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
                    ValueOp::Set(value)
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
        value: impl Into<TagValue>,
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

    pub fn blob(&mut self, hash: BlobHash, op: BlobOp, options: u32) -> &mut Self {
        self.ops.push(Operation::Blob {
            hash,
            op,
            set: !options.has_flag(F_CLEAR),
        });
        self
    }

    pub fn add(&mut self, class: impl Into<ValueClass>, value: i64) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::Add(value),
        });
        self
    }

    pub fn set(&mut self, class: impl Into<ValueClass>, value: impl Into<Vec<u8>>) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::Set(value.into()),
        });
        self
    }

    pub fn clear(&mut self, class: impl Into<ValueClass>) -> &mut Self {
        self.ops.push(Operation::Value {
            class: class.into(),
            op: ValueOp::Clear,
        });
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

impl Default for BatchBuilder {
    fn default() -> Self {
        Self::new()
    }
}
