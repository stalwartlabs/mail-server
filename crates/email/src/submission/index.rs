/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{IndexValue, IndexableObject};
use jmap_proto::types::property::Property;

use super::EmailSubmission;

impl IndexableObject for EmailSubmission {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Text {
                field: Property::UndoStatus.into(),
                value: self.undo_status.as_index().as_bytes().into(),
            },
            IndexValue::U32 {
                field: Property::EmailId.into(),
                value: Some(self.email_id),
            },
            IndexValue::U32 {
                field: Property::ThreadId.into(),
                value: Some(self.thread_id),
            },
            IndexValue::U32 {
                field: Property::IdentityId.into(),
                value: Some(self.identity_id),
            },
            IndexValue::U64 {
                field: Property::SendAt.into(),
                value: Some(self.send_at),
            },
        ]
        .into_iter()
    }
}
