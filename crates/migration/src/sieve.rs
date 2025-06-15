/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::object::Object;
use crate::object::TryFromLegacy;
use common::Server;
use email::sieve::{SieveScript, VacationResponse};
use jmap_proto::types::{collection::Collection, property::Property, value::Value};
use store::{
    SUBSPACE_BITMAP_TEXT, SUBSPACE_INDEXES, SUBSPACE_PROPERTY, Serialize, U64_LEN, ValueKey,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, ValueClass, key::KeySerializer,
    },
};
use trc::{AddContext, StoreEvent};

pub(crate) async fn migrate_sieve(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let script_ids = server
        .get_document_ids(account_id, Collection::SieveScript)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_scripts = script_ids.len();
    if num_scripts == 0 {
        return Ok(0);
    }
    let mut did_migrate = false;

    // Delete indexes
    for subspace in [SUBSPACE_INDEXES, SUBSPACE_BITMAP_TEXT] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::SieveScript))
                        .finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::SieveScript))
                        .write(&[u8::MAX; 16][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    for script_id in &script_ids {
        match server
            .store()
            .get_value::<Object<Value>>(ValueKey {
                account_id,
                collection: Collection::SieveScript.into(),
                document_id: script_id,
                class: ValueClass::Property(Property::Value.into()),
            })
            .await
        {
            Ok(Some(legacy)) => {
                if let Some(script) = SieveScript::try_from_legacy(legacy) {
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::SieveScript)
                        .update_document(script_id)
                        .index(
                            Property::IsActive,
                            if script.is_active {
                                vec![1u8]
                            } else {
                                vec![0u8]
                            },
                        )
                        .index(Property::Name, script.name.to_lowercase())
                        .set(
                            Property::Value,
                            Archiver::new(script)
                                .serialize()
                                .caused_by(trc::location!())?,
                        );
                    did_migrate = true;

                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                } else {
                    trc::event!(
                        Store(StoreEvent::DataCorruption),
                        Details = "Failed to migrate SieveScript",
                        AccountId = account_id,
                    )
                }
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey {
                        account_id,
                        collection: Collection::SieveScript.into(),
                        document_id: script_id,
                        class: ValueClass::Property(Property::Value.into()),
                    })
                    .await
                    .is_err()
                {
                    return Err(err
                        .account_id(account_id)
                        .document_id(script_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    // Delete emailIds property
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_PROPERTY,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::SieveScript))
                    .write(u8::from(Property::EmailIds))
                    .finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_PROPERTY,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::SieveScript))
                    .write(u8::from(Property::EmailIds))
                    .write(&[u8::MAX; 8][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Increment document id counter
    if did_migrate {
        server
            .store()
            .assign_document_ids(
                account_id,
                Collection::SieveScript,
                script_ids.max().map(|id| id as u64).unwrap_or(num_scripts) + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_scripts)
    } else {
        Ok(0)
    }
}

impl TryFromLegacy for SieveScript {
    fn try_from_legacy(legacy: Object<Value>) -> Option<Self> {
        let blob_id = legacy.get(&Property::BlobId).as_blob_id()?;
        Some(SieveScript {
            name: legacy
                .get(&Property::Name)
                .as_string()
                .unwrap_or_default()
                .to_string(),
            is_active: legacy
                .get(&Property::IsActive)
                .as_bool()
                .unwrap_or_default(),
            blob_hash: blob_id.hash.clone(),
            size: blob_id.section.as_ref()?.size as u32,
            vacation_response: VacationResponse::try_from_legacy(legacy),
        })
    }
}

impl TryFromLegacy for VacationResponse {
    fn try_from_legacy(legacy: Object<Value>) -> Option<Self> {
        let vacation = VacationResponse {
            from_date: legacy
                .get(&Property::FromDate)
                .as_date()
                .map(|s| s.timestamp() as u64),
            to_date: legacy
                .get(&Property::ToDate)
                .as_date()
                .map(|s| s.timestamp() as u64),
            subject: legacy
                .get(&Property::Name)
                .as_string()
                .map(|s| s.to_string()),
            text_body: legacy
                .get(&Property::TextBody)
                .as_string()
                .map(|s| s.to_string()),
            html_body: legacy
                .get(&Property::HtmlBody)
                .as_string()
                .map(|s| s.to_string()),
        };

        if vacation.from_date.is_some()
            || vacation.to_date.is_some()
            || vacation.subject.is_some()
            || vacation.text_body.is_some()
            || vacation.html_body.is_some()
        {
            Some(vacation)
        } else {
            None
        }
    }
}
