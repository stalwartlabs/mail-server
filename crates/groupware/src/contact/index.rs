/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{
    IndexItem, IndexValue, IndexableAndSerializableObject, IndexableObject,
};
use jmap_proto::types::value::AclGrant;
use store::SerializeInfallible;

use crate::{IDX_CARD_UID, IDX_NAME};

use super::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};

impl IndexableObject for AddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        // Note: When adding a new value with index id above 0u8, tune `build_hierarchy`` to skip
        // this value during iteration.
        [
            IndexValue::Index {
                field: IDX_NAME,
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
            IndexValue::Index {
                field: IDX_NAME,
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
            IndexValue::IndexList {
                field: IDX_NAME,
                value: self
                    .names
                    .iter()
                    .map(|v| IndexItem::Vec(v.serialize()))
                    .collect::<Vec<_>>(),
            },
            IndexValue::Index {
                field: IDX_CARD_UID,
                value: self.card.uid().into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::IndexList {
                field: IDX_NAME,
                value: self
                    .names
                    .iter()
                    .map(|v| IndexItem::Vec(v.serialize()))
                    .collect::<Vec<_>>(),
            },
            IndexValue::Index {
                field: IDX_CARD_UID,
                value: self.card.uid().into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for ContactCard {}
