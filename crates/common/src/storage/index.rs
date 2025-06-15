/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use jmap_proto::types::{property::Property, value::AclGrant};
use rkyv::{
    option::ArchivedOption,
    primitive::{ArchivedU32, ArchivedU64},
    string::ArchivedString,
};
use std::{borrow::Cow, fmt::Debug};
use store::{
    Serialize, SerializeInfallible,
    write::{Archive, Archiver, BatchBuilder, BlobOp, DirectoryClass, IntoOperations, TagValue},
};
use utils::BlobHash;

use crate::auth::AsTenantId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexValue<'x> {
    Index {
        field: u8,
        value: IndexItem<'x>,
    },
    IndexList {
        field: u8,
        value: Vec<IndexItem<'x>>,
    },
    Tag {
        field: u8,
        value: Vec<TagValue>,
    },
    Blob {
        value: BlobHash,
    },
    Quota {
        used: u32,
    },
    LogContainer {
        sync_collection: u8,
    },
    LogContainerProperty {
        sync_collection: u8,
        ids: Vec<u32>,
    },
    LogItem {
        sync_collection: u8,
        prefix: Option<u32>,
    },
    Acl {
        value: Cow<'x, [AclGrant]>,
    },
}

#[derive(Debug, Clone)]
pub enum IndexItem<'x> {
    Vec(Vec<u8>),
    Slice(&'x [u8]),
    ShortInt([u8; std::mem::size_of::<u32>()]),
    LongInt([u8; std::mem::size_of::<u64>()]),
    None,
}

impl IndexItem<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s,
            IndexItem::ShortInt(s) => s,
            IndexItem::LongInt(s) => s,
            IndexItem::None => &[],
        }
    }

    pub fn into_owned(self) -> Vec<u8> {
        match self {
            IndexItem::Vec(v) => v,
            IndexItem::Slice(s) => s.to_vec(),
            IndexItem::ShortInt(s) => s.to_vec(),
            IndexItem::LongInt(s) => s.to_vec(),
            IndexItem::None => vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            IndexItem::Vec(v) => v.is_empty(),
            IndexItem::Slice(s) => s.is_empty(),
            IndexItem::None => true,
            _ => false,
        }
    }
}

impl PartialEq for IndexItem<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for IndexItem<'_> {}

impl std::hash::Hash for IndexItem<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            IndexItem::Vec(v) => v.as_slice().hash(state),
            IndexItem::Slice(s) => s.hash(state),
            IndexItem::ShortInt(s) => s.as_slice().hash(state),
            IndexItem::LongInt(s) => s.as_slice().hash(state),
            IndexItem::None => 0.hash(state),
        }
    }
}

impl From<u32> for IndexItem<'_> {
    fn from(value: u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<&u32> for IndexItem<'_> {
    fn from(value: &u32) -> Self {
        IndexItem::ShortInt(value.to_be_bytes())
    }
}

impl From<u64> for IndexItem<'_> {
    fn from(value: u64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl From<i64> for IndexItem<'_> {
    fn from(value: i64) -> Self {
        IndexItem::LongInt(value.to_be_bytes())
    }
}

impl<'x> From<&'x [u8]> for IndexItem<'x> {
    fn from(value: &'x [u8]) -> Self {
        IndexItem::Slice(value)
    }
}

impl From<Vec<u8>> for IndexItem<'_> {
    fn from(value: Vec<u8>) -> Self {
        IndexItem::Vec(value)
    }
}

impl<'x> From<&'x str> for IndexItem<'x> {
    fn from(value: &'x str) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl<'x> From<&'x String> for IndexItem<'x> {
    fn from(value: &'x String) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<String> for IndexItem<'_> {
    fn from(value: String) -> Self {
        IndexItem::Vec(value.into_bytes())
    }
}

impl<'x> From<&'x ArchivedString> for IndexItem<'x> {
    fn from(value: &'x ArchivedString) -> Self {
        IndexItem::Slice(value.as_bytes())
    }
}

impl From<ArchivedU32> for IndexItem<'_> {
    fn from(value: ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<&ArchivedU32> for IndexItem<'_> {
    fn from(value: &ArchivedU32) -> Self {
        IndexItem::ShortInt(value.to_native().to_be_bytes())
    }
}

impl From<ArchivedU64> for IndexItem<'_> {
    fn from(value: ArchivedU64) -> Self {
        IndexItem::LongInt(value.to_native().to_be_bytes())
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<Option<T>> for IndexItem<'x> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => v.into(),
            None => IndexItem::None,
        }
    }
}

impl<'x, T: Into<IndexItem<'x>>> From<ArchivedOption<T>> for IndexItem<'x> {
    fn from(value: ArchivedOption<T>) -> Self {
        match value {
            ArchivedOption::Some(v) => v.into(),
            ArchivedOption::None => IndexItem::None,
        }
    }
}

pub trait IndexableObject: Sync + Send {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>>;
}

pub trait IndexableAndSerializableObject:
    IndexableObject
    + rkyv::Archive
    + for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            rkyv::rancor::Error,
        >,
    >
{
    fn is_versioned() -> bool;
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
                if N::is_versioned() {
                    let (offset, bytes) = Archiver::new(changes).serialize_versioned()?;
                    batch.set_versioned(Property::Value, bytes, offset);
                } else {
                    batch.set(Property::Value, Archiver::new(changes).serialize()?);
                }
            }
            (Some(current), Some(changes)) => {
                // Update
                batch.assert_value(Property::Value, &current);
                for (current, change) in current.inner.index_values().zip(changes.index_values()) {
                    if current != change {
                        merge_index(batch, current, change, self.tenant_id)?;
                    } else {
                        match current {
                            IndexValue::LogContainer { sync_collection } => {
                                batch.log_container_update(sync_collection);
                            }
                            IndexValue::LogItem {
                                sync_collection,
                                prefix,
                            } => {
                                batch.log_item_update(sync_collection, prefix);
                            }
                            _ => (),
                        }
                    }
                }
                if N::is_versioned() {
                    let (offset, bytes) = Archiver::new(changes).serialize_versioned()?;
                    batch.set_versioned(Property::Value, bytes, offset);
                } else {
                    batch.set(Property::Value, Archiver::new(changes).serialize()?);
                }
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
        IndexValue::Index { field, value } => {
            if !value.is_empty() {
                if set {
                    batch.index(field, value.into_owned());
                } else {
                    batch.unindex(field, value.into_owned());
                }
            }
        }
        IndexValue::IndexList { field, value } => {
            for key in value {
                if set {
                    batch.index(field, key.into_owned());
                } else {
                    batch.unindex(field, key.into_owned());
                }
            }
        }
        IndexValue::Tag { field, value } => {
            for item in value {
                if set {
                    batch.tag(field, item);
                } else {
                    batch.untag(field, item);
                }
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
                if set {
                    batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                } else {
                    batch.acl_revoke(item.account_id);
                }
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
        IndexValue::LogItem {
            sync_collection,
            prefix,
        } => {
            if set {
                batch.log_item_insert(sync_collection, prefix);
            } else {
                batch.log_item_delete(sync_collection, prefix);
            }
        }
        IndexValue::LogContainer { sync_collection } => {
            if set {
                batch.log_container_insert(sync_collection);
            } else {
                batch.log_container_delete(sync_collection);
            }
        }
        IndexValue::LogContainerProperty {
            sync_collection,
            ids,
        } => {
            for parent_id in ids {
                batch.log_container_property_change(sync_collection, parent_id);
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
            IndexValue::Index {
                field,
                value: old_value,
            },
            IndexValue::Index {
                value: new_value, ..
            },
        ) => {
            if !old_value.is_empty() {
                batch.unindex(field, old_value.into_owned());
            }

            if !new_value.is_empty() {
                batch.index(field, new_value.into_owned());
            }
        }
        (
            IndexValue::IndexList {
                field,
                value: old_value,
            },
            IndexValue::IndexList {
                value: new_value, ..
            },
        ) => {
            let mut remove_values = AHashSet::from_iter(old_value);

            for value in new_value {
                if !remove_values.remove(&value) {
                    batch.index(field, value.into_owned());
                }
            }

            for value in remove_values {
                batch.unindex(field, value.into_owned());
            }
        }
        (
            IndexValue::Tag {
                field,
                value: old_value,
            },
            IndexValue::Tag {
                value: new_value, ..
            },
        ) => {
            for old_tag in &old_value {
                if !new_value.contains(old_tag) {
                    batch.untag(field, old_tag.clone());
                }
            }

            for new_tag in new_value {
                if !old_value.contains(&new_tag) {
                    batch.tag(field, new_tag);
                }
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
                            batch.acl_revoke(current_item.account_id);
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
                            batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                        }
                    }
                }
                (false, true) => {
                    // Add all ACLs
                    for item in new_acl.as_ref() {
                        batch.acl_grant(item.account_id, item.grants.bitmap.serialize());
                    }
                }
                (true, false) => {
                    // Remove all ACLs
                    for item in old_acl.as_ref() {
                        batch.acl_revoke(item.account_id);
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
        (
            IndexValue::LogItem {
                sync_collection,
                prefix: old_prefix,
            },
            IndexValue::LogItem {
                prefix: new_prefix, ..
            },
        ) => {
            batch.log_item_delete(sync_collection, old_prefix);
            batch.log_item_insert(sync_collection, new_prefix);
        }
        (
            IndexValue::LogContainerProperty {
                sync_collection,
                ids: old_ids,
            },
            IndexValue::LogContainerProperty { ids: new_ids, .. },
        ) => {
            for parent_id in &old_ids {
                if !new_ids.contains(parent_id) {
                    batch.log_container_property_change(sync_collection, *parent_id);
                }
            }
            for parent_id in new_ids {
                if !old_ids.contains(&parent_id) {
                    batch.log_container_property_change(sync_collection, parent_id);
                }
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

impl IndexableAndSerializableObject for () {
    fn is_versioned() -> bool {
        false
    }
}
