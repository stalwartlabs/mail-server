/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, property::Property};
use store::write::BatchBuilder;
use trc::AddContext;

use super::SieveScript;

pub trait SieveScriptDelete: Sync + Send {
    fn sieve_script_delete(
        &self,
        resource_token: &ResourceToken,
        document_id: u32,
        fail_if_active: bool,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<Option<bool>>> + Send;
}

impl SieveScriptDelete for Server {
    async fn sieve_script_delete(
        &self,
        resource_token: &ResourceToken,
        document_id: u32,
        fail_if_active: bool,
        batch: &mut BatchBuilder,
    ) -> trc::Result<Option<bool>> {
        // Fetch record
        let account_id = resource_token.account_id;
        let obj_ = if let Some(obj) = self
            .get_archive(account_id, Collection::SieveScript, document_id)
            .await?
        {
            obj
        } else {
            return Ok(None);
        };

        let obj = obj_
            .to_unarchived::<SieveScript>()
            .caused_by(trc::location!())?;

        // Make sure the script is not active
        if fail_if_active && obj.inner.is_active {
            return Ok(Some(false));
        }

        // Delete record
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .delete_document(document_id)
            .clear(Property::EmailIds)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_current(obj)
                    .with_tenant_id(resource_token),
            )
            .caused_by(trc::location!())?
            .commit_point();

        Ok(Some(true))
    }
}
