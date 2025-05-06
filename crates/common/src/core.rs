/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Duration};

use directory::{Directory, QueryBy, Type, backend::internal::manage::ManageDirectory};
use jmap_proto::types::{
    blob::BlobId,
    collection::{Collection, SyncCollection},
    property::Property,
    state::StateChange,
    type_state::DataType,
};
use sieve::Sieve;
use store::{
    BitmapKey, BlobClass, BlobStore, Deserialize, FtsStore, InMemoryStore, IndexKey, IterateParams,
    LogKey, SerializeInfallible, Store, U32_LEN, ValueKey,
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive, AssignedIds, BatchBuilder, BlobOp, DirectoryClass, QueueClass,
        ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use utils::BlobHash;

use crate::{
    Inner, Server,
    auth::{AccessToken, ResourceToken, TenantInfo},
    config::smtp::{
        auth::{ArcSealer, DkimSigner, LazySignature, ResolvedSignature, build_signature},
        queue::RelayHost,
    },
    ipc::StateEvent,
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

    pub fn get_arc_sealer(&self, name: &str, session_id: u64) -> Option<Arc<ArcSealer>> {
        self.resolve_signature(name).map(|s| s.sealer).or_else(|| {
            trc::event!(
                Arc(trc::ArcEvent::SealerNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    pub fn get_dkim_signer(&self, name: &str, session_id: u64) -> Option<Arc<DkimSigner>> {
        self.resolve_signature(name).map(|s| s.signer).or_else(|| {
            trc::event!(
                Dkim(trc::DkimEvent::SignerNotFound),
                Id = name.to_string(),
                SpanId = session_id,
            );

            None
        })
    }

    fn resolve_signature(&self, name: &str) -> Option<ResolvedSignature> {
        let lazy_resolver_ = self.core.smtp.mail_auth.signatures.get(name)?;
        match lazy_resolver_.load().as_ref() {
            LazySignature::Resolved(resolved_signature) => Some(resolved_signature.clone()),
            LazySignature::Pending(config) => {
                let mut config = config.clone();
                if let Some((signer, sealer)) = build_signature(&mut config, name) {
                    let resolved = ResolvedSignature {
                        signer: Arc::new(signer),
                        sealer: Arc::new(sealer),
                    };
                    lazy_resolver_.store(Arc::new(LazySignature::Resolved(resolved.clone())));
                    Some(resolved)
                } else {
                    config.log_errors();
                    lazy_resolver_.store(Arc::new(LazySignature::Failed));
                    None
                }
            }
            LazySignature::Failed => None,
        }
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

    pub async fn recalculate_quota(&self, account_id: u32) -> trc::Result<()> {
        let mut quota = 0i64;

        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        field: Property::Size.into(),
                        key: 0u32.serialize(),
                    },
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        field: Property::Size.into(),
                        key: u32::MAX.serialize(),
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    let value = key
                        .get(key.len() - (U32_LEN * 2)..key.len() - U32_LEN)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))
                        .and_then(u32::deserialize)?;

                    quota += value as i64;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        batch
            .clear(DirectoryClass::UsedQuota(account_id))
            .add(DirectoryClass::UsedQuota(account_id), quota);
        self.store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())
            .map(|_| ())
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

    #[inline(always)]
    pub async fn get_archive(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        self.core
            .storage
            .data
            .get_value(ValueKey {
                account_id,
                collection: collection.into(),
                document_id,
                class: ValueClass::Property(Property::Value.into()),
            })
            .await
            .add_context(|err| {
                err.caused_by(trc::location!())
                    .account_id(account_id)
                    .collection(collection)
                    .document_id(document_id)
            })
    }

    #[inline(always)]
    pub async fn get_archive_by_property(
        &self,
        account_id: u32,
        collection: Collection,
        document_id: u32,
        property: impl AsRef<Property> + Sync + Send,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        let property = property.as_ref();
        self.core
            .storage
            .data
            .get_value(ValueKey {
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
            })
    }

    pub async fn get_archives<I, CB>(
        &self,
        account_id: u32,
        collection: Collection,
        documents: &I,
        mut cb: CB,
    ) -> trc::Result<()>
    where
        I: DocumentSet + Send + Sync,
        CB: FnMut(u32, Archive<AlignedBytes>) -> trc::Result<bool> + Send + Sync,
    {
        let collection: u8 = collection.into();

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.min(),
                        class: ValueClass::Property(Property::Value.into()),
                    },
                    ValueKey {
                        account_id,
                        collection,
                        document_id: documents.max(),
                        class: ValueClass::Property(Property::Value.into()),
                    },
                ),
                |key, value| {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if documents.contains(document_id) {
                        <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                            .and_then(|archive| cb(document_id, archive))
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
            })
    }

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
    pub fn generate_snowflake_id(&self) -> u64 {
        self.inner.data.jmap_id_gen.generate()
    }

    pub async fn commit_batch(&self, mut builder: BatchBuilder) -> trc::Result<AssignedIds> {
        let mut assigned_ids = AssignedIds::default();

        for batch in builder.build() {
            assigned_ids = self.store().write(batch).await?;
        }

        if let Some(changes) = builder.changes() {
            for (account_id, changed_collections) in changes {
                let mut state_change = StateChange::new(account_id);
                let change_id = changed_collections.change_id;
                for changed_collection in changed_collections.changed_containers {
                    if let Some(data_type) = DataType::try_from_id(changed_collection, true) {
                        state_change.set_change(data_type, change_id);
                    }
                }
                for changed_collection in changed_collections.changed_items {
                    if let Some(data_type) = DataType::try_from_id(changed_collection, false) {
                        state_change.set_change(data_type, change_id);
                    }
                }
                if state_change.has_changes() {
                    self.broadcast_state_change(state_change).await;
                }
                assigned_ids.change_id = change_id.into();
            }
        }

        Ok(assigned_ids)
    }

    pub async fn delete_changes(&self, account_id: u32, before: Duration) -> trc::Result<()> {
        let reference_cid = self.inner.data.jmap_id_gen.past_id(before).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference change id.")
        })?;

        for collection in [
            SyncCollection::Email.into(),
            SyncCollection::Thread.into(),
            SyncCollection::Identity.into(),
            SyncCollection::EmailSubmission.into(),
            SyncCollection::SieveScript.into(),
            SyncCollection::FileNode.into(),
            SyncCollection::AddressBook.into(),
            SyncCollection::Calendar.into(),
        ] {
            self.core
                .storage
                .data
                .delete_range(
                    LogKey {
                        account_id,
                        collection,
                        change_id: 0,
                    },
                    LogKey {
                        account_id,
                        collection,
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
        let hash = BlobHash::generate(data);
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
            .write(batch.build_all())
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
                .write(batch.build_all())
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

    pub fn increment_config_version(&self) {
        self.inner
            .data
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
