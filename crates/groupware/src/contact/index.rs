/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use jmap_proto::types::{property::Property, value::AclGrant};

use super::{AddressBook, ArchivedAddressBook, ContactCard};

impl IndexableObject for AddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.as_str().into(),
            },
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.description.as_ref().map_or(0, |n| n.len() as u32)
                    + self.name.len() as u32,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedAddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.as_str().into(),
            },
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.description.as_ref().map_or(0, |n| n.len() as u32)
                    + self.name.len() as u32,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for AddressBook {}

impl IndexableObject for ContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.as_str().into(),
            },
            IndexValue::U32List {
                field: Property::ParentId.into(),
                value: self.addressbook_ids.as_slice().into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.name.len() as u32
                    + self.size,
            },
        ]
        .into_iter()
    }
}
