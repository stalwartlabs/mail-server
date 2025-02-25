/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{collection::Collection, property::Property};
use store::write::{ArchivedValue, BatchBuilder, BlobOp, assert::HashedValue};
use trc::AddContext;

use super::ArchivedSieveScript;

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
        let obj = self
            .get_property::<HashedValue<ArchivedValue<ArchivedSieveScript>>>(
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
            })?
            .into_deserialized()
            .caused_by(trc::location!())?;

        // Make sure the script is not active
        if fail_if_active && obj.inner.is_active {
            return Ok(false);
        }

        let blob_hash = obj.inner.blob_hash.clone();
        let mut builder = ObjectIndexBuilder::new().with_current(obj);
        // Update tenant quota
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            if let Some(tenant) = resource_token.tenant {
                builder.set_tenant_id(tenant.id);
            }
        }

        // Delete record
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .delete_document(document_id)
            .clear(Property::EmailIds)
            .clear(BlobOp::Link { hash: blob_hash })
            .custom(builder)
            .caused_by(trc::location!())?;

        self.store()
            .write(batch)
            .await
            .caused_by(trc::location!())?;
        Ok(true)
    }
}
