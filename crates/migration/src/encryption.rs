/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::message::crypto::EncryptionParams;
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    Deserialize, Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, ValueClass},
};
use trc::AddContext;

pub(crate) async fn migrate_encryption_params(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    match server
        .store()
        .get_value::<LegacyEncryptionParams>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(Property::Parameters.into()),
        })
        .await
    {
        Ok(Some(legacy)) => {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .update_document(0)
                .set(
                    Property::Parameters,
                    Archiver::new(legacy.0)
                        .serialize()
                        .caused_by(trc::location!())?,
                );

            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            return Ok(1);
        }
        Ok(None) => (),
        Err(err) => {
            if server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey {
                    account_id,
                    collection: Collection::Principal.into(),
                    document_id: 0,
                    class: ValueClass::Property(Property::Parameters.into()),
                })
                .await
                .is_err()
            {
                return Err(err.account_id(account_id).caused_by(trc::location!()));
            }
        }
    }
    Ok(0)
}

struct LegacyEncryptionParams(EncryptionParams);

impl Deserialize for LegacyEncryptionParams {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let version = *bytes
            .first()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        match version {
            1 if bytes.len() > 1 => bincode::deserialize(&bytes[1..])
                .map(LegacyEncryptionParams)
                .map_err(|err| {
                    trc::EventType::Store(trc::StoreEvent::DeserializeError)
                        .reason(err)
                        .caused_by(trc::location!())
                }),

            _ => Err(trc::StoreEvent::DeserializeError
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, version as u64)),
        }
    }
}
