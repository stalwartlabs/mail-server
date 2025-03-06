/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::{
    folder::FolderHierarchy,
    index::{IndexValue, IndexableObject},
};
use jmap_proto::types::property::Property;

use super::{ArchivedFileNode, FileNode};

impl IndexableObject for FileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let size = self.dead_properties.size() as u32
            + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
            + self.name.len() as u32;

        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Text {
                field: Property::Name.into(),
                value: self.name.to_lowercase().into(),
            },
            IndexValue::U32 {
                field: Property::ParentId.into(),
                value: self.parent_id.into(),
            },
            IndexValue::Acl { value: &self.acls },
        ]);

        if let Some(file) = &self.file {
            let size = size + file.size;
            values.extend([
                IndexValue::Blob {
                    value: file.blob_hash.clone(),
                },
                IndexValue::U32 {
                    field: Property::Size.into(),
                    value: size.into(),
                },
                IndexValue::Quota { used: size },
            ]);
        } else {
            values.push(IndexValue::Quota { used: size });
        }

        values.into_iter()
    }
}

impl FolderHierarchy for ArchivedFileNode {
    fn name(&self) -> String {
        self.name.to_string()
    }

    fn parent_id(&self) -> u32 {
        u32::from(self.parent_id)
    }
}
