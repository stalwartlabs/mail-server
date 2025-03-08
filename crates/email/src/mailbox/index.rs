/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::jmap::settings::{ArchivedSpecialUse, SpecialUse},
    storage::{
        folder::FolderHierarchy,
        index::{IndexValue, IndexableAndSerializableObject, IndexableObject},
    },
};
use jmap_proto::types::{property::Property, value::AclGrant};
use store::write::{MaybeDynamicId, TagValue};

use super::{ArchivedMailbox, ArchivedUidMailbox, Mailbox, UidMailbox};

impl IndexableObject for Mailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::Text {
                field: Property::Role.into(),
                value: self.role.as_str().unwrap_or_default().into(),
            },
            IndexValue::Tag {
                field: Property::Role.into(),
                is_set: !matches!(self.role, SpecialUse::None),
            },
            IndexValue::U32 {
                field: Property::ParentId.into(),
                value: self.parent_id.into(),
            },
            IndexValue::U32 {
                field: Property::SortOrder.into(),
                value: self.sort_order,
            },
            IndexValue::U32List {
                field: Property::IsSubscribed.into(),
                value: (&self.subscribers).into(),
            },
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedMailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::Text {
                field: Property::Role.into(),
                value: self.role.as_str().unwrap_or_default().into(),
            },
            IndexValue::Tag {
                field: Property::Role.into(),
                is_set: !matches!(self.role, ArchivedSpecialUse::None),
            },
            IndexValue::U32 {
                field: Property::ParentId.into(),
                value: u32::from(self.parent_id).into(),
            },
            IndexValue::U32 {
                field: Property::SortOrder.into(),
                value: self.sort_order.as_ref().map(u32::from),
            },
            IndexValue::U32List {
                field: Property::IsSubscribed.into(),
                value: self
                    .subscribers
                    .iter()
                    .map(u32::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Mailbox {}

impl FolderHierarchy for ArchivedMailbox {
    fn name(&self) -> String {
        self.name.to_string()
    }

    fn parent_id(&self) -> u32 {
        u32::from(self.parent_id)
    }

    fn is_container(&self) -> bool {
        true
    }

    fn size(&self) -> u32 {
        0
    }
}

impl From<&UidMailbox> for TagValue<MaybeDynamicId> {
    fn from(value: &UidMailbox) -> Self {
        TagValue::Id(MaybeDynamicId::Static(value.mailbox_id))
    }
}

impl From<UidMailbox> for TagValue<MaybeDynamicId> {
    fn from(value: UidMailbox) -> Self {
        TagValue::Id(MaybeDynamicId::Static(value.mailbox_id))
    }
}

impl From<&ArchivedUidMailbox> for TagValue<MaybeDynamicId> {
    fn from(value: &ArchivedUidMailbox) -> Self {
        TagValue::Id(MaybeDynamicId::Static(value.mailbox_id.into()))
    }
}
