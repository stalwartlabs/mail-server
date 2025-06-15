/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedFileNode, FileNode};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use jmap_proto::types::{collection::SyncCollection, value::AclGrant};

impl IndexableObject for FileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode.into(),
            },
            IndexValue::Quota { used: self.size() },
        ]);

        if let Some(file) = &self.file {
            values.extend([IndexValue::Blob {
                value: file.blob_hash.clone(),
            }]);
        }

        values.into_iter()
    }
}

impl IndexableObject for &ArchivedFileNode {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        let mut values = Vec::with_capacity(6);

        values.extend([
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::LogItem {
                prefix: None,
                sync_collection: SyncCollection::FileNode.into(),
            },
            IndexValue::Quota { used: self.size() },
        ]);

        if let Some(file) = self.file.as_ref() {
            values.extend([IndexValue::Blob {
                value: (&file.blob_hash).into(),
            }]);
        }

        values.into_iter()
    }
}

impl IndexableAndSerializableObject for FileNode {
    fn is_versioned() -> bool {
        true
    }
}

pub trait NodeSize {
    fn size(&self) -> u32;
}

impl NodeSize for ArchivedFileNode {
    fn size(&self) -> u32 {
        self.dead_properties.size() as u32
            + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
            + self.name.len() as u32
            + self.file.as_ref().map_or(0, |f| u32::from(f.size))
    }
}

impl NodeSize for FileNode {
    fn size(&self) -> u32 {
        self.dead_properties.size() as u32
            + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
            + self.name.len() as u32
            + self.file.as_ref().map_or(0, |f| f.size)
    }
}
