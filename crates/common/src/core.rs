/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use directory::{backend::internal::manage::ManageDirectory, Directory, QueryBy, Type};
use jmap_proto::types::{
    blob::BlobId, collection::Collection, property::Property, state::StateChange,
};
use sieve::Sieve;
use store::{
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    write::{
        key::DeserializeBigEndian, log::ChangeLogBuilder, now, BatchBuilder, BitmapClass, BlobOp,
        DirectoryClass, QueueClass, TagValue, ValueClass,
    },
    BitmapKey, BlobClass, BlobStore, Deserialize, FtsStore, InMemoryStore, IterateParams, LogKey,
    Serialize, Store, ValueKey, U32_LEN,
};
use trc::AddContext;
use utils::BlobHash;

use crate::{
    auth::{AccessToken, ResourceToken, TenantInfo},
    config::smtp::{
        auth::{ArcSealer, DkimSigner},
        queue::RelayHost,
    },
    ipc::StateEvent,
    ImapId, Inner, MailboxState, Server,
};

impl Server {
    #[inline(always)]
    pub fn store(&self) -> &Store {
        &self.core.storage.data
    }

    #[inline(always)]
    pub fn blob_store(&self) -> &BlobStore {
        &self.core.storage.blob
    }

    #[inline(always)]
    pub fn fts_store(&self) -> &FtsStore {
        &self.core.storage.fts
    }

    #[inline(always)]
    pub fn in_memory_store(&self) -> &InMemoryStore {
        &self.core.storage.lookup
    }

    #[inline(always)]
    pub fn directory(&self) -> &Directory {
        &self.core.storage.directory
    }

    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.core.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str, session_id: u64) -> &Arc<Directory> {
        self.core.storage.directories.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::DirectoryNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.directory
        })
    }

    pub fn get_in_memory_store(&self, name: &str) -> Option<&InMemoryStore> {
        self.core.storage.lookups.get(name)
    }

    pub fn get_in_memory_store_or_default(&self, name: &str, session_id: u64) -> &InMemoryStore {
        self.core.storage.lookups.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::StoreNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.lookup
        })
    }

    pub fn get_data_store(&self, name: &str, session_id: u64) -> &Store {
        self.core.storage.stores.get(name).unwrap_or_else(|| {
            if !name.is_empty() {
                trc::event!(
                    Eval(trc::EvalEvent::StoreNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );
            }

            &self.core.storage.data
        })
    }

    pub fn get_arc_sealer(&self, name: &str, session_id: u64) -> Option<&ArcSealer> {
        self.core
            .smtp
            .mail_auth
            .sealers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                trc::event!(
                    Arc(trc::ArcEvent::SealerNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );

                None
            })
    }

    pub fn get_dkim_signer(&self, name: &str, session_id: u64) -> Option<&DkimSigner> {
        self.core
            .smtp
            .mail_auth
            .signers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                trc::event!(
                    Dkim(trc::DkimEvent::SignerNotFound),
                    Id = name.to_string(),
                    SpanId = session_id,
                );

                None
            })
    }

    pub fn get_trusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.trusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_untrusted_sieve_script(&self, name: &str, session_id: u64) -> Option<&Arc<Sieve>> {
        self.core.sieve.untrusted_scripts.get(name).or_else(|| {
            trc::event!(
                Sieve(trc::SieveEvent::ScriptNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_relay_host(&self, name: &str, session_id: u64) -> Option<&RelayHost> {
        self.core.smtp.queue.relay_hosts.get(name).or_else(|| {
            trc::event!(
                Smtp(trc::SmtpEvent::RemoteIdNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub async fn get_used_quota(&self, account_id: u32) -> trc::Result<i64> {
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(account_id))
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
    }

    pub async fn has_available_quota(
        &self,
        quotas: &ResourceToken,
        item_size: u64,
    ) -> trc::Result<()> {
        if quotas.quota != 0 {
            let used_quota = self.get_used_quota(quotas.account_id).await? as u64;

            if used_quota + item_size > quotas.quota {
                return Err(trc::LimitEvent::Quota
                    .into_err()
                    .ctx(trc::Key::Limit, quotas.quota)
                    .ctx(trc::Key::Size, used_quota));
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            if let Some(tenant) = quotas.tenant.filter(|tenant| tenant.quota != 0) {
                let used_quota = self.get_used_quota(tenant.id).await? as u64;

                if used_quota + item_size > tenant.quota {
                    return Err(trc::LimitEvent::TenantQuota
                        .into_err()
                        .ctx(trc::Key::Limit, tenant.quota)
                        .ctx(trc::Key::Size, used_quota));
                }
            }
        }

        // SPDX-SnippetEnd

        Ok(())
    }

    pub async fn get_resource_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<ResourceToken> {
        Ok(if access_token.primary_id == account_id {
            ResourceToken {
                account_id,
                quota: access_token.quota,
                tenant: access_token.tenant,
            }
        } else {
            let mut quotas = ResourceToken {
                account_id,
                ..Default::default()
            };

            if let Some(principal) = self
                .core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))?
            {
                quotas.quota = principal.quota();

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() {
                    if let Some(tenant_id) = principal.tenant() {
                        quotas.tenant = TenantInfo {
                            id: tenant_id,
                            quota: self
                                .core
                                .storage
                                .directory
                                .query(QueryBy::Id(tenant_id), false)
                                .await
                                .add_context(|err| {
                                    err.caused_by(trc::location!()).account_id(tenant_id)
                                })?
                                .map(|tenant| tenant.quota())
                                .unwrap_or_default(),
                        }
                        .into();
                    }
                }

                // SPDX-SnippetEnd
            }

            quotas
        })
    }

    pub async fn get_property<U>(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property> + Sync + Send,
    ) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        let property = property.as_ref();

        self.core
            .storage
            .data
            .get_value::<U>(ValueKey {
                account_id,
                collection: collection.into(),
                document_id,
                class: ValueClass::Property(property.into()),
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .document_id(document_id)
                    .id(property.to_string())
            })
    }

    pub async fn get_properties<U, I, P>(
        &self,
        account_id: u32,
        collection: Collection,
        iterate: &I,
        property: P,
    ) -> trc::Result<Vec<(u32, U)>>
    where
        I: DocumentSet + Send + Sync,
        P: AsRef<Property> + Sync + Send,
        U: Deserialize + 'static,
    {
        let property: u8 = property.as_ref().into();
        let collection: u8 = collection.into();
        let expected_results = iterate.len();
        let mut results = Vec::with_capacity(expected_results);

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: iterate.min(),
                        class: ValueClass::Property(property),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: iterate.max(),
                        class: ValueClass::Property(property),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if iterate.contains(document_id) {
                        results.push((document_id, U::deserialize(value)?));
                        Ok(expected_results == 0 || results.len() < expected_results)
                    } else {
                        Ok(true)
                    }
                },
            )
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .id(property.to_string())
            })
            .map(|_| results)
    }

    pub async fn get_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> trc::Result<Option<RoaringBitmap>> {
        self.core
            .storage
            .data
            .get_bitmap(BitmapKey::document_ids(account_id, collection))
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
            })
    }

    pub async fn get_tag(
        &self,
        account_id: u32,
        collection: Collection,
        property: impl AsRef<Property> + Sync + Send,
        value: impl Into<TagValue<u32>> + Sync + Send,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let property = property.as_ref();
        self.core
            .storage
            .data
            .get_bitmap(BitmapKey {
                account_id,
                collection: collection.into(),
                class: BitmapClass::Tag {
                    field: property.into(),
                    value: value.into(),
                },
                document_id: 0,
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .id(property.to_string())
            })
    }

    pub fn notify_task_queue(&self) {
        self.inner.ipc.index_tx.notify_one();
    }

    pub async fn total_queued_messages(&self) -> trc::Result<u64> {
        let mut total = 0;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(0))),
                    ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX))),
                )
                .no_values(),
                |_, _| {
                    total += 1;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| total)
    }

    pub fn begin_changes(&self, account_id: u32) -> trc::Result<ChangeLogBuilder> {
        self.assign_change_id(account_id)
            .map(ChangeLogBuilder::with_change_id)
    }

    #[inline(always)]
    pub fn assign_change_id(&self, _: u32) -> trc::Result<u64> {
        self.generate_snowflake_id()
    }

    pub fn generate_snowflake_id(&self) -> trc::Result<u64> {
        self.inner.data.jmap_id_gen.generate().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate snowflake id.")
        })
    }

    pub async fn commit_changes(
        &self,
        account_id: u32,
        mut changes: ChangeLogBuilder,
    ) -> trc::Result<u64> {
        if changes.change_id == u64::MAX || changes.change_id == 0 {
            changes.change_id = self.assign_change_id(account_id)?;
        }
        let state = changes.change_id;

        let mut builder = BatchBuilder::new();
        builder.with_account_id(account_id).custom(changes);
        self.core
            .storage
            .data
            .write(builder.build())
            .await
            .caused_by(trc::location!())
            .map(|_| state)
    }

    pub async fn delete_changes(&self, account_id: u32, before: Duration) -> trc::Result<()> {
        let reference_cid = self.inner.data.jmap_id_gen.past_id(before).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference change id.")
        })?;

        for collection in [
            Collection::Email,
            Collection::Mailbox,
            Collection::Thread,
            Collection::Identity,
            Collection::EmailSubmission,
        ] {
            self.core
                .storage
                .data
                .delete_range(
                    LogKey {
                        account_id,
                        collection: collection.into(),
                        change_id: 0,
                    },
                    LogKey {
                        account_id,
                        collection: collection.into(),
                        change_id: reference_cid,
                    },
                )
                .await?;
        }

        Ok(())
    }

    pub async fn broadcast_state_change(&self, state_change: StateChange) -> bool {
        match self
            .inner
            .ipc
            .state_tx
            .clone()
            .send(StateEvent::Publish { state_change })
            .await
        {
            Ok(_) => true,
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Error sending state change.",
                    CausedBy = trc::location!()
                );

                false
            }
        }
    }

    #[allow(clippy::blocks_in_conditions)]
    pub async fn put_blob(
        &self,
        account_id: u32,
        data: &[u8],
        set_quota: bool,
    ) -> trc::Result<BlobId> {
        // First reserve the hash
        let hash = BlobHash::from(data);
        let mut batch = BatchBuilder::new();
        let until = now() + self.core.jmap.upload_tmp_ttl;

        batch.with_account_id(account_id).set(
            BlobOp::Reserve {
                hash: hash.clone(),
                until,
            },
            (if set_quota { data.len() as u32 } else { 0u32 }).serialize(),
        );
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .caused_by(trc::location!())?;

        if !self
            .core
            .storage
            .data
            .blob_exists(&hash)
            .await
            .caused_by(trc::location!())?
        {
            // Upload blob to store
            self.core
                .storage
                .blob
                .put_blob(hash.as_ref(), data)
                .await
                .caused_by(trc::location!())?;

            // Commit blob
            let mut batch = BatchBuilder::new();
            batch.set(BlobOp::Commit { hash: hash.clone() }, Vec::new());
            self.core
                .storage
                .data
                .write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(BlobId {
            hash,
            class: BlobClass::Reserved {
                account_id,
                expires: until,
            },
            section: None,
        })
    }

    pub async fn total_accounts(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Individual.into(), None)
            .await
            .caused_by(trc::location!())
    }

    pub async fn total_domains(&self) -> trc::Result<u64> {
        self.store()
            .count_principals(None, Type::Domain.into(), None)
            .await
            .caused_by(trc::location!())
    }
}

pub trait BuildServer {
    fn build_server(&self) -> Server;
}

impl BuildServer for Arc<Inner> {
    fn build_server(&self) -> Server {
        Server {
            inner: self.clone(),
            core: self.shared_core.load_full(),
        }
    }
}

impl MailboxState {
    pub fn map_result_id(&self, document_id: u32, is_uid: bool) -> Option<(u32, ImapId)> {
        if let Some(imap_id) = self.id_to_imap.get(&document_id) {
            Some((if is_uid { imap_id.uid } else { imap_id.seqnum }, *imap_id))
        } else if is_uid {
            self.next_state.as_ref().and_then(|s| {
                s.next_state
                    .id_to_imap
                    .get(&document_id)
                    .map(|imap_id| (imap_id.uid, *imap_id))
            })
        } else {
            None
        }
    }
}
