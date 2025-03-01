/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    SerializeInfallible,
    query::Filter,
    write::{Archive, BatchBuilder, assert::HashedValue},
};
use trc::AddContext;

use super::SieveScript;

pub trait SieveScriptActivate: Sync + Send {
    fn sieve_activate_script(
        &self,
        account_id: u32,
        activate_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<Vec<(u32, bool)>>> + Send;
}

impl SieveScriptActivate for Server {
    async fn sieve_activate_script(
        &self,
        account_id: u32,
        mut activate_id: Option<u32>,
    ) -> trc::Result<Vec<(u32, bool)>> {
        let mut changed_ids = Vec::new();
        // Find the currently active script
        let mut active_ids = self
            .store()
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::IsActive, 1u32.serialize())],
            )
            .await?
            .results;

        // Check if script is already active
        if activate_id.is_some_and(|id| active_ids.remove(id)) {
            if active_ids.is_empty() {
                return Ok(changed_ids);
            } else {
                activate_id = None;
            }
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript);

        // Deactivate scripts
        for document_id in active_ids {
            if let Some(sieve) = self
                .get_property::<HashedValue<Archive>>(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                let sieve = sieve
                    .into_deserialized::<SieveScript>()
                    .caused_by(trc::location!())?;
                let mut new_sieve = sieve.inner.clone();
                new_sieve.is_active = false;
                batch
                    .update_document(document_id)
                    .clear(Property::EmailIds)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_changes(new_sieve)
                            .with_current(sieve),
                    )
                    .caused_by(trc::location!())?;
                changed_ids.push((document_id, false));
            }
        }

        // Activate script
        if let Some(document_id) = activate_id {
            if let Some(sieve) = self
                .get_property::<HashedValue<Archive>>(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                let sieve = sieve
                    .into_deserialized::<SieveScript>()
                    .caused_by(trc::location!())?;
                let mut new_sieve = sieve.inner.clone();
                new_sieve.is_active = true;
                batch
                    .update_document(document_id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_changes(new_sieve)
                            .with_current(sieve),
                    )
                    .caused_by(trc::location!())?;
                changed_ids.push((document_id, true));
            }
        }

        // Write changes
        if !changed_ids.is_empty() {
            match self.core.storage.data.write(batch.build()).await {
                Ok(_) => (),
                Err(err) if err.is_assertion_failure() => {
                    return Ok(vec![]);
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        Ok(changed_ids)
    }
}
