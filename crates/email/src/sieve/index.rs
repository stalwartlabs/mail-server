/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use jmap_proto::types::property::Property;

use super::{ArchivedSieveScript, SieveScript};

impl IndexableObject for SieveScript {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::U32 {
                field: Property::IsActive.into(),
                value: Some(self.is_active as u32),
            },
            IndexValue::Blob {
                value: self.blob_hash.clone(),
            },
            IndexValue::Quota { used: self.size },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for SieveScript {}

impl IndexableObject for &ArchivedSieveScript {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::U32 {
                field: Property::IsActive.into(),
                value: Some(self.is_active as u32),
            },
            IndexValue::Blob {
                value: (&self.blob_hash).into(),
            },
            IndexValue::Quota {
                used: u32::from(self.size),
            },
        ]
        .into_iter()
    }
}
