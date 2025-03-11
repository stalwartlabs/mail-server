/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{property::Property, value::AclGrant};
use std::{borrow::Cow, collections::HashSet, fmt::Debug};
use store::{
    Serialize, SerializeInfallible, SerializedVersion,
    write::{
        Archive, Archiver, BatchBuilder, BitmapClass, BlobOp, DirectoryClass, IntoOperations,
        Operation,
    },
};
use utils::BlobHash;

use crate::auth::AsTenantId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue<'x> {
    Text { field: u8, value: Cow<'x, str> },
    U32 { field: u8, value: Option<u32> },
    U64 { field: u8, value: Option<u64> },
    U32List { field: u8, value: Cow<'x, [u32]> },
    Tag { field: u8, is_set: bool },
    Blob { value: BlobHash },
    Quota { used: u32 },
    Acl { value: Cow<'x, [AclGrant]> },
}

pub trait IndexableObject: Sync + Send {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
}

pub trait IndexableAndSerializableObject:
    IndexableObject
    + SerializedVersion
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    >
{
}

#[derive(Debug)]
pub struct ObjectIndexBuilder<C: IndexableObject, N: IndexableAndSerializableObject> {
    tenant_id: Option<u32>,
    current: Option<Archive<C>>,
    changes: Option<N>,
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> Default for ObjectIndexBuilder<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> ObjectIndexBuilder<C, N> {
    pub fn new() -> Self {
        Self {
            current: None,
            changes: None,
            tenant_id: None,
        }
    }

    pub fn with_current(mut self, current: Archive<C>) -> Self {
        self.current = Some(current);
        self
    }

    pub fn with_changes(mut self, changes: N) -> Self {
        self.changes = Some(changes);
        self
    }

    pub fn with_current_opt(mut self, current: Option<Archive<C>>) -> Self {
        self.current = current;
        self
    }

    pub fn changes(&self) -> Option<&N> {
        self.changes.as_ref()
    }

    pub fn changes_mut(&mut self) -> Option<&mut N> {
        self.changes.as_mut()
    }

    pub fn current(&self) -> Option<&Archive<C>> {
        self.current.as_ref()
    }

    pub fn with_tenant_id(mut self, tenant: &impl AsTenantId) -> Self {
        self.tenant_id = tenant.tenant_id();
        self
    }
}

impl<C: IndexableObject, N: IndexableAndSerializableObject> IntoOperations
    for ObjectIndexBuilder<C, N>
{
    fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        match (self.current, self.changes) {
            (None, Some(changes)) => {
                // Insertion
                for item in changes.index_values() {
                    build_index(batch, item, self.tenant_id, true);
                }
                batch.set(Property::Value, Archiver::new(changes).serialize()?);
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Property::Value, &current);
                for (current, change) in current.inner.index_values().zip(changes.index_values()) {
                    if current != change {
                        merge_index(batch, current, change, self.tenant_id)?;
                    }
                }
                batch.set(Property::Value, Archiver::new(changes).serialize()?);
            }
            (Some(current), None) => {
                // Deletion
                batch.assert_value(Property::Value, &current);
                for item in current.inner.index_values() {
                    build_index(batch, item, self.tenant_id, false);
                }

                batch.clear(Property::Value);
            }
            (None, None) => unreachable!(),
        }

        Ok(())
    }
}

fn build_index(batch: &mut BatchBuilder, item: IndexValue<'_>, tenant_id: Option<u32>, set: bool) {
    match item {
        IndexValue::Text { field, value } => {
            if !value.is_empty() {
                batch.ops.push(Operation::Index {
                    field,
                    key: value.into_owned().into_bytes(),
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
            for item in value.as_ref() {
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
        IndexValue::Blob { value } => {
            if set {
                batch.set(BlobOp::Link { hash: value }, vec![]);
            } else {
                batch.clear(BlobOp::Link { hash: value });
            }
        }
        IndexValue::Acl { value } => {
            for item in value.as_ref() {
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

fn merge_index(
    batch: &mut BatchBuilder,
    current: IndexValue<'_>,
    change: IndexValue<'_>,
    tenant_id: Option<u32>,
) -> trc::Result<()> {
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
                    key: old_value.into_owned().into_bytes(),
                    set: false,
                });
            }

            if !new_value.is_empty() {
                batch.ops.push(Operation::Index {
                    field,
                    key: new_value.into_owned().into_bytes(),
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

            for current_value in old_value.as_ref() {
                remove_values.insert(current_value);
            }
            for value in new_value.as_ref() {
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
        (IndexValue::Blob { value: old_hash }, IndexValue::Blob { value: new_hash }) => {
            batch.clear(BlobOp::Link { hash: old_hash });
            batch.set(BlobOp::Link { hash: new_hash }, vec![]);
        }
        (IndexValue::Acl { value: old_acl }, IndexValue::Acl { value: new_acl }) => {
            match (!old_acl.is_empty(), !new_acl.is_empty()) {
                (true, true) => {
                    // Remove deleted ACLs
                    for current_item in old_acl.as_ref() {
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
                    for item in new_acl.as_ref() {
                        let mut add_item = true;
                        for current_item in old_acl.as_ref() {
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
                    for item in new_acl.as_ref() {
                        batch.ops.push(Operation::acl(
                            item.account_id,
                            item.grants.bitmap.serialize().into(),
                        ));
                    }
                }
                (true, false) => {
                    // Remove all ACLs
                    for item in old_acl.as_ref() {
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

    Ok(())
}

impl IndexableObject for () {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        std::iter::empty()
    }
}

impl IndexableAndSerializableObject for () {}
