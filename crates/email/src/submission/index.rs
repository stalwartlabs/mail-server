/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use jmap_proto::types::{collection::SyncCollection, property::Property};

use super::{ArchivedEmailSubmission, EmailSubmission};

impl IndexableObject for EmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: Property::UndoStatus.into(),
                value: self.undo_status.as_index().into(),
            },
            IndexValue::Index {
                field: Property::EmailId.into(),
                value: self.email_id.into(),
            },
            IndexValue::Index {
                field: Property::ThreadId.into(),
                value: self.thread_id.into(),
            },
            IndexValue::Index {
                field: Property::IdentityId.into(),
                value: self.identity_id.into(),
            },
            IndexValue::Index {
                field: Property::SendAt.into(),
                value: self.send_at.into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::EmailSubmission.into(),
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedEmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: Property::UndoStatus.into(),
                value: self.undo_status.as_index().into(),
            },
            IndexValue::Index {
                field: Property::EmailId.into(),
                value: self.email_id.into(),
            },
            IndexValue::Index {
                field: Property::ThreadId.into(),
                value: self.thread_id.into(),
            },
            IndexValue::Index {
                field: Property::IdentityId.into(),
                value: self.identity_id.into(),
            },
            IndexValue::Index {
                field: Property::SendAt.into(),
                value: self.send_at.into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::EmailSubmission.into(),
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for EmailSubmission {
    fn is_versioned() -> bool {
        false
    }
}
