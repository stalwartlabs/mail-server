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
        let mut filters = Vec::with_capacity(5);
        filters.extend([
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
            filters.extend([
                IndexValue::U32 {
                    field: Property::Size.into(),
                    value: file.size.into(),
                },
                IndexValue::Quota { used: file.size },
            ]);
        }

        filters.into_iter()
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
