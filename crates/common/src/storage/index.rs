/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{property::Property, value::AclGrant};
use std::{borrow::Cow, collections::HashSet, fmt::Debug};
use store::{
    Serialize, SerializeInfallible,
    write::{
        Archiver, BatchBuilder, BitmapClass, DirectoryClass, IntoOperations, Operation, ValueOp,
        assert::HashedValue,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue<'x> {
    Text { field: u8, value: Cow<'x, [u8]> },
    U32 { field: u8, value: Option<u32> },
    U64 { field: u8, value: Option<u64> },
    U32List { field: u8, value: &'x [u32] },
    Tag { field: u8, is_set: bool },
    Quota { used: u32 },
    Acl { value: &'x [AclGrant] },
}

pub trait IndexableObject:
    Debug
    + Eq
    + Sync
    + Send
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    >
{
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
}

#[derive(Debug)]
pub struct ObjectIndexBuilder<T: IndexableObject> {
    tenant_id: Option<u32>,
    current: Option<HashedValue<T>>,
    changes: Option<T>,
}

impl<'x> IndexValue<'x> {
    pub fn queryable_text(field: impl Into<u8>, text: &'x str) -> Self {
        let mut value = Vec::with_capacity((text.len() * 2) + 1);
        value.extend_from_slice(text.as_bytes());
        value.push(0);
        value.extend_from_slice(text.to_lowercase().as_bytes());

        IndexValue::Text {
            field: field.into(),
            value: value.into(),
        }
    }
}

impl<T: IndexableObject> Default for ObjectIndexBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: IndexableObject> ObjectIndexBuilder<T> {
    pub fn new() -> Self {
        Self {
            current: None,
            changes: None,
            tenant_id: None,
        }
    }

    pub fn with_current(mut self, current: HashedValue<T>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: T) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<HashedValue<T>>) -> Self {
        self.current = current;
        self
    }

    pub fn changes(&self) -> Option<&T> {
        self.changes.as_ref()
    }

    pub fn changes_mut(&mut self) -> Option<&mut T> {
        self.changes.as_mut()
    }

    pub fn current(&self) -> Option<&HashedValue<T>> {
        self.current.as_ref()
    }

    pub fn with_tenant_id(mut self, tenant_id: Option<u32>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    pub fn set_tenant_id(&mut self, tenant_id: u32) {
        self.tenant_id = tenant_id.into();
    }
}

impl<T: IndexableObject> IntoOperations for ObjectIndexBuilder<T> {
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                build_batch(batch, &changes, self.tenant_id, true);
                batch.set(Property::Value, Archiver::new(changes).serialize()?);
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Property::Value, &current);
                merge_batch(batch, current.inner, changes, self.tenant_id)?;
            }
            (Some(current), None) => {
                // Deletion
                batch.assert_value(Property::Value, &current);
                build_batch(batch, &current.inner, self.tenant_id, false);
                batch.clear(Property::Value);
            }
            (None, None) => unreachable!(),
        }

        Ok(())
    }
}

fn build_batch<T: IndexableObject>(
    batch: &mut BatchBuilder,
    object: &T,
    tenant_id: Option<u32>,
    set: bool,
) {
    for item in object.index_values() {
        match item {
            IndexValue::Text { field, value } => {
                if !value.is_empty() {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.into_owned(),
                        set,
                    });
                }
            }
            IndexValue::U32 { field, value } => {
                if let Some(value) = value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set,
                    });
                }
            }
            IndexValue::U64 { field, value } => {
                if let Some(value) = value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set,
                    });
                }
            }
            IndexValue::U32List { field, value } => {
                for item in value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: (*item).serialize(),
                        set,
                    });
                }
            }
            IndexValue::Tag { field, is_set } => {
                if is_set {
                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Tag {
                            field,
                            value: ().into(),
                        },
                        set,
                    });
                }
            }
            IndexValue::Acl { value } => {
                for item in value {
                    batch.ops.push(Operation::acl(
                        item.account_id,
                        if set {
                            item.grants.bitmap.serialize().into()
                        } else {
                            None
                        },
                    ));
                }
            }
            IndexValue::Quota { used } => {
                let value = if set { used as i64 } else { -(used as i64) };

                if let Some(account_id) = batch.last_account_id() {
                    batch.add(DirectoryClass::UsedQuota(account_id), value);
                }

                if let Some(tenant_id) = tenant_id {
                    batch.add(DirectoryClass::UsedQuota(tenant_id), value);
                }
            }
        }
    }
}

fn merge_batch<T: IndexableObject>(
    batch: &mut BatchBuilder,
    current: T,
    changes: T,
    tenant_id: Option<u32>,
) -> trc::Result<()> {
    let mut has_changes = current != changes;

    for (current, change) in current.index_values().zip(changes.index_values()) {
        if current == change {
            continue;
        }
        has_changes = true;

        match (current, change) {
            (
                IndexValue::Text {
                    field,
                    value: old_value,
                },
                IndexValue::Text {
                    value: new_value, ..
                },
            ) => {
                if !old_value.is_empty() {
                    batch.ops.push(Operation::Index {
                        field,
                        key: old_value.into_owned(),
                        set: false,
                    });
                }

                if !new_value.is_empty() {
                    batch.ops.push(Operation::Index {
                        field,
                        key: new_value.into_owned(),
                        set: true,
                    });
                }
            }
            (
                IndexValue::U32 {
                    field,
                    value: old_value,
                },
                IndexValue::U32 {
                    value: new_value, ..
                },
            ) => {
                if let Some(value) = old_value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set: false,
                    });
                }
                if let Some(value) = new_value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set: true,
                    });
                }
            }
            (
                IndexValue::U64 {
                    field,
                    value: old_value,
                },
                IndexValue::U64 {
                    value: new_value, ..
                },
            ) => {
                if let Some(value) = old_value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set: false,
                    });
                }
                if let Some(value) = new_value {
                    batch.ops.push(Operation::Index {
                        field,
                        key: value.serialize(),
                        set: true,
                    });
                }
            }
            (
                IndexValue::U32List {
                    field,
                    value: old_value,
                },
                IndexValue::U32List {
                    value: new_value, ..
                },
            ) => {
                let mut add_values = HashSet::new();
                let mut remove_values = HashSet::new();

                for current_value in old_value {
                    remove_values.insert(current_value);
                }
                for value in new_value {
                    if !remove_values.remove(&value) {
                        add_values.insert(value);
                    }
                }

                for (values, set) in [(add_values, true), (remove_values, false)] {
                    for value in values {
                        batch.ops.push(Operation::Index {
                            field,
                            key: value.serialize(),
                            set,
                        });
                    }
                }
            }
            (
                IndexValue::Tag {
                    field,
                    is_set: was_set,
                },
                IndexValue::Tag { is_set, .. },
            ) => {
                if was_set {
                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Tag {
                            field,
                            value: ().into(),
                        },
                        set: false,
                    });
                }
                if is_set {
                    batch.ops.push(Operation::Bitmap {
                        class: BitmapClass::Tag {
                            field,
                            value: ().into(),
                        },
                        set: true,
                    });
                }
            }
            (IndexValue::Acl { value: old_acl }, IndexValue::Acl { value: new_acl }) => {
                match (!old_acl.is_empty(), !new_acl.is_empty()) {
                    (true, true) => {
                        // Remove deleted ACLs
                        for current_item in old_acl {
                            if !new_acl
                                .iter()
                                .any(|item| item.account_id == current_item.account_id)
                            {
                                batch
                                    .ops
                                    .push(Operation::acl(current_item.account_id, None));
                            }
                        }

                        // Update ACLs
                        for item in new_acl {
                            let mut add_item = true;
                            for current_item in old_acl {
                                if item.account_id == current_item.account_id {
                                    if item.grants == current_item.grants {
                                        add_item = false;
                                    }
                                    break;
                                }
                            }
                            if add_item {
                                batch.ops.push(Operation::acl(
                                    item.account_id,
                                    item.grants.bitmap.serialize().into(),
                                ));
                            }
                        }
                    }
                    (false, true) => {
                        // Add all ACLs
                        for item in new_acl {
                            batch.ops.push(Operation::acl(
                                item.account_id,
                                item.grants.bitmap.serialize().into(),
                            ));
                        }
                    }
                    (true, false) => {
                        // Remove all ACLs
                        for item in old_acl {
                            batch.ops.push(Operation::acl(item.account_id, None));
                        }
                    }
                    _ => {}
                }
            }
            (IndexValue::Quota { used: old_used }, IndexValue::Quota { used: new_used }) => {
                let value = new_used as i64 - old_used as i64;
                if let Some(account_id) = batch.last_account_id() {
                    batch.add(DirectoryClass::UsedQuota(account_id), value);
                }

                if let Some(tenant_id) = tenant_id {
                    batch.add(DirectoryClass::UsedQuota(tenant_id), value);
                }
            }
            _ => unreachable!(),
        }
    }

    if has_changes {
        batch.ops.push(Operation::Value {
            class: Property::Value.into(),
            op: ValueOp::Set(Archiver::new(changes).serialize()?.into()),
        });
    }

    Ok(())
}
