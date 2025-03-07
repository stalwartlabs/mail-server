/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, property::Property};
use store::write::{Archive, BatchBuilder, assert::HashedValue};
use trc::AddContext;

use super::SieveScript;

pub trait SieveScriptDelete: Sync + Send {
    fn sieve_script_delete(
        &self,
        resource_token: &ResourceToken,
        document_id: u32,
        fail_if_active: bool,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl SieveScriptDelete for Server {
    async fn sieve_script_delete(
        &self,
        resource_token: &ResourceToken,
        document_id: u32,
        fail_if_active: bool,
    ) -> trc::Result<bool> {
        // Fetch record
        let account_id = resource_token.account_id;
        let obj_ = self
            .get_property::<HashedValue<Archive>>(
                account_id,
                Collection::SieveScript,
                document_id,
                Property::Value,
            )
            .await?
            .ok_or_else(|| {
                trc::StoreEvent::NotFound
                    .into_err()
                    .caused_by(trc::location!())
                    .document_id(document_id)
            })?;
        let obj = obj_
            .to_unarchived::<SieveScript>()
            .caused_by(trc::location!())?;

        // Make sure the script is not active
        if fail_if_active && obj.inner.is_active {
            return Ok(false);
        }

        // Delete record
        let mut batch = BatchBuilder::new();
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
            .caused_by(trc::location!())?;

        self.store()
            .write(batch)
            .await
            .caused_by(trc::location!())?;
        Ok(true)
    }
}
