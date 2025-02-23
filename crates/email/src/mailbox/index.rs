/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::jmap::settings::SpecialUse;
use jmap_proto::{
    object::index::{IndexValue, IndexableObject},
    types::property::Property,
};

use super::Mailbox;

impl IndexableObject for Mailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.as_str(),
                tokenize: true,
                index: true,
            },
            IndexValue::Text {
                field: Property::Role.into(),
                value: self.role.as_str().unwrap_or_default(),
                tokenize: false,
                index: true,
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
                value: &self.subscribers,
            },
            IndexValue::Acl { value: &self.acls },
        ]
        .into_iter()
    }
}
