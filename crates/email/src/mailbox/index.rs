/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use jmap_proto::types::{collection::SyncCollection, value::AclGrant};

use super::{ArchivedMailbox, Mailbox};

impl IndexableObject for Mailbox {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email.into(),
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
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Email.into(),
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

impl IndexableAndSerializableObject for Mailbox {
    fn is_versioned() -> bool {
        false
    }
}
