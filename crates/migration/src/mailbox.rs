/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::object::Object;
use crate::object::FromLegacy;
use common::{Server, config::jmap::settings::SpecialUse};
use email::mailbox::Mailbox;
use jmap_proto::types::{collection::Collection, property::Property, value::Value};
use store::{
    SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT, SUBSPACE_INDEXES, Serialize, U64_LEN, ValueKey,
    rand,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, ValueClass, key::KeySerializer,
    },
};
use trc::AddContext;
use utils::config::utils::ParseValue;

pub(crate) async fn migrate_mailboxes(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let mailbox_ids = server
        .get_document_ids(account_id, Collection::Mailbox)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_mailboxes = mailbox_ids.len();
    if num_mailboxes == 0 {
        return Ok(0);
    }
    let mut did_migrate = false;

    for mailbox_id in &mailbox_ids {
        match server
            .store()
            .get_value::<Object<Value>>(ValueKey {
                account_id,
                collection: Collection::Mailbox.into(),
                document_id: mailbox_id,
                class: ValueClass::Property(Property::Value.into()),
            })
            .await
        {
            Ok(Some(legacy)) => {
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Mailbox)
                    .update_document(mailbox_id)
                    .set(
                        Property::Value,
                        Archiver::new(Mailbox::from_legacy(legacy))
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                did_migrate = true;

                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey {
                        account_id,
                        collection: Collection::Mailbox.into(),
                        document_id: mailbox_id,
                        class: ValueClass::Property(Property::Value.into()),
                    })
                    .await
                    .is_err()
                {
                    return Err(err
                        .account_id(account_id)
                        .document_id(mailbox_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    // Delete indexes
    for subspace in [SUBSPACE_INDEXES, SUBSPACE_BITMAP_TAG, SUBSPACE_BITMAP_TEXT] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Mailbox))
                        .finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Mailbox))
                        .write(&[u8::MAX; 16][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    // Increment document id counter
    if did_migrate {
        server
            .store()
            .assign_document_ids(
                account_id,
                Collection::Mailbox,
                mailbox_ids
                    .max()
                    .map(|id| id as u64)
                    .unwrap_or(num_mailboxes)
                    + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_mailboxes)
    } else {
        Ok(0)
    }
}

impl FromLegacy for Mailbox {
    fn from_legacy(legacy: Object<Value>) -> Self {
        Mailbox {
            name: legacy
                .get(&Property::Name)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            role: legacy
                .get(&Property::Role)
                .as_string()
                .and_then(|r| SpecialUse::parse_value(r).ok())
                .unwrap_or(SpecialUse::None),
            parent_id: legacy
                .get(&Property::ParentId)
                .as_uint()
                .unwrap_or_default() as u32,
            sort_order: legacy.get(&Property::SortOrder).as_uint().map(|s| s as u32),
            uid_validity: rand::random(),
            subscribers: legacy
                .get(&Property::IsSubscribed)
                .as_list()
                .map(|s| s.as_slice())
                .unwrap_or_default()
                .iter()
                .filter_map(|s| s.as_uint())
                .map(|s| s as u32)
                .collect(),
            acls: legacy
                .get(&Property::Acl)
                .as_acl()
                .cloned()
                .unwrap_or_default(),
        }
    }
}
