/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{query::Filter, write::BatchBuilder};
use trc::AddContext;

use super::SieveScript;

pub trait SieveScriptActivate: Sync + Send {
    fn sieve_activate_script(
        &self,
        account_id: u32,
        activate_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<(u64, Vec<(u32, bool)>)>> + Send;
}

impl SieveScriptActivate for Server {
    async fn sieve_activate_script(
        &self,
        account_id: u32,
        mut activate_id: Option<u32>,
    ) -> trc::Result<(u64, Vec<(u32, bool)>)> {
        let mut changed_ids = Vec::new();
        // Find the currently active script
        let mut active_ids = self
            .store()
            .filter(
                account_id,
                Collection::SieveScript,
                vec![Filter::eq(Property::IsActive, vec![1u8])],
            )
            .await?
            .results;

        // Check if script is already active
        if activate_id.is_some_and(|id| active_ids.remove(id)) {
            if active_ids.is_empty() {
                return Ok((0, changed_ids));
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
            if let Some(sieve_) = self
                .get_archive(account_id, Collection::SieveScript, document_id)
                .await?
            {
                let sieve = sieve_
                    .to_unarchived::<SieveScript>()
                    .caused_by(trc::location!())?;
                let mut new_sieve = sieve.deserialize().caused_by(trc::location!())?;
                new_sieve.is_active = false;
                batch
                    .update_document(document_id)
                    .clear(Property::EmailIds)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_changes(new_sieve)
                            .with_current(sieve),
                    )
                    .caused_by(trc::location!())?
                    .commit_point();
                changed_ids.push((document_id, false));
            }
        }

        // Activate script
        if let Some(document_id) = activate_id {
            if let Some(sieve_) = self
                .get_archive(account_id, Collection::SieveScript, document_id)
                .await?
            {
                let sieve = sieve_
                    .to_unarchived::<SieveScript>()
                    .caused_by(trc::location!())?;
                let mut new_sieve = sieve.deserialize().caused_by(trc::location!())?;
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
            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id) => Ok((change_id, changed_ids)),
                Err(err) if err.is_assertion_failure() => Ok((0, vec![])),
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        } else {
            Ok((0, changed_ids))
        }
    }
}
