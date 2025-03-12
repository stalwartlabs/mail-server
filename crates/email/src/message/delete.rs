/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::{KV_LOCK_PURGE_ACCOUNT, Server, storage::index::ObjectIndexBuilder};
use jmap_proto::types::{
    collection::Collection, id::Id, property::Property, state::StateChange, type_state::DataType,
};
use store::{
    BitmapKey, IterateParams, U32_LEN, ValueKey,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive, BatchBuilder, BitmapClass, MaybeDynamicId, TagValue, ValueClass,
        log::{ChangeLogBuilder, Changes},
    },
};
use trc::AddContext;
use utils::{BlobHash, codec::leb128::Leb128Reader};

use std::future::Future;
use store::rand::prelude::SliceRandom;

use crate::{mailbox::*, message::metadata::MessageMetadata};

use super::metadata::MessageData;

pub trait EmailDeletion: Sync + Send {
    fn emails_tombstone(
        &self,
        account_id: u32,
        document_ids: RoaringBitmap,
    ) -> impl Future<Output = trc::Result<(ChangeLogBuilder, RoaringBitmap)>> + Send;

    fn purge_accounts(&self) -> impl Future<Output = ()> + Send;

    fn purge_account(&self, account_id: u32) -> impl Future<Output = ()> + Send;

    fn emails_auto_expunge(
        &self,
        account_id: u32,
        period: Duration,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn emails_purge_tombstoned(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn emails_purge_threads(&self, account_id: u32)
    -> impl Future<Output = trc::Result<()>> + Send;
}

impl EmailDeletion for Server {
    async fn emails_tombstone(
        &self,
        account_id: u32,
        mut document_ids: RoaringBitmap,
    ) -> trc::Result<(ChangeLogBuilder, RoaringBitmap)> {
        // Create batch
        let mut changes = ChangeLogBuilder::with_change_id(0);

        // Tombstone message and untag it from the mailboxes
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);

        for (document_id, data_) in self
            .get_properties::<Archive<AlignedBytes>, _>(
                account_id,
                Collection::Email,
                &document_ids,
                Property::Value,
            )
            .await?
        {
            let data = data_
                .to_unarchived::<MessageData>()
                .caused_by(trc::location!())?;
            let thread_id = u32::from(data.inner.thread_id);

            for mailbox in data.inner.mailboxes.iter() {
                changes.log_child_update(Collection::Mailbox, u32::from(mailbox.mailbox_id));
            }

            // Log message deletion
            changes.log_delete(Collection::Email, Id::from_parts(thread_id, document_id));

            // Log thread changes
            changes.log_child_update(Collection::Thread, thread_id);

            // Add changes to batch
            batch
                .update_document(document_id)
                .custom(ObjectIndexBuilder::<_, ()>::new().with_current(data))
                .caused_by(trc::location!())?
                .tag(
                    Property::MailboxIds,
                    TagValue::Id(MaybeDynamicId::Static(TOMBSTONE_ID)),
                );

            document_ids.remove(document_id);

            if batch.ops.len() >= 1000 {
                self.core
                    .storage
                    .data
                    .write(batch.build())
                    .await
                    .caused_by(trc::location!())?;

                batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email);
            }
        }

        if !batch.ops.is_empty() {
            self.core
                .storage
                .data
                .write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok((changes, document_ids))
    }

    async fn purge_accounts(&self) {
        if let Ok(Some(account_ids)) = self.get_document_ids(u32::MAX, Collection::Principal).await
        {
            let mut account_ids: Vec<u32> = account_ids.into_iter().collect();

            // Shuffle account ids
            account_ids.shuffle(&mut store::rand::rng());

            for account_id in account_ids {
                self.purge_account(account_id).await;
            }
        }
    }

    async fn purge_account(&self, account_id: u32) {
        // Lock account
        match self
            .core
            .storage
            .lookup
            .try_lock(KV_LOCK_PURGE_ACCOUNT, &account_id.to_be_bytes(), 3600)
            .await
        {
            Ok(true) => (),
            Ok(false) => {
                trc::event!(Purge(trc::PurgeEvent::InProgress), AccountId = account_id,);
                return;
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock account.")
                        .account_id(account_id)
                );
                return;
            }
        }

        // Auto-expunge deleted and junk messages
        if let Some(period) = self.core.jmap.mail_autoexpunge_after {
            if let Err(err) = self.emails_auto_expunge(account_id, period).await {
                trc::error!(
                    err.details("Failed to auto-expunge messages.")
                        .account_id(account_id)
                );
            }
        }

        // Purge tombstoned messages
        if let Err(err) = self.emails_purge_tombstoned(account_id).await {
            trc::error!(
                err.details("Failed to purge tombstoned messages.")
                    .account_id(account_id)
            );
        }

        // Purge changelogs
        if let Some(history) = self.core.jmap.changes_max_history {
            if let Err(err) = self.delete_changes(account_id, history).await {
                trc::error!(
                    err.details("Failed to purge changes.")
                        .account_id(account_id)
                );
            }
        }

        // Delete lock
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_PURGE_ACCOUNT, &account_id.to_be_bytes())
            .await
        {
            trc::error!(err.details("Failed to delete lock.").account_id(account_id));
        }
    }

    async fn emails_auto_expunge(&self, account_id: u32, period: Duration) -> trc::Result<()> {
        let deletion_candidates = self
            .get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                TagValue::Id(TRASH_ID),
            )
            .await?
            .unwrap_or_default()
            | self
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    TagValue::Id(JUNK_ID),
                )
                .await?
                .unwrap_or_default();

        if deletion_candidates.is_empty() {
            return Ok(());
        }
        let reference_cid = self.inner.data.jmap_id_gen.past_id(period).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference cid.")
        })?;

        // Find messages to destroy
        let mut destroy_ids = RoaringBitmap::new();
        for (document_id, data) in self
            .get_properties::<Archive<AlignedBytes>, _>(
                account_id,
                Collection::Email,
                &deletion_candidates,
                Property::Value,
            )
            .await?
        {
            if data.unarchive::<MessageData>()?.change_id < reference_cid {
                destroy_ids.insert(document_id);
            }
        }

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Tombstone messages
        let (changes, _) = self.emails_tombstone(account_id, destroy_ids).await?;

        // Write and broadcast changes
        if !changes.is_empty() {
            let change_id = self.commit_changes(account_id, changes).await?;
            self.broadcast_state_change(
                StateChange::new(account_id)
                    .with_change(DataType::Email, change_id)
                    .with_change(DataType::Mailbox, change_id)
                    .with_change(DataType::Thread, change_id),
            )
            .await;
        }

        Ok(())
    }

    async fn emails_purge_tombstoned(&self, account_id: u32) -> trc::Result<()> {
        // Obtain tombstoned messages
        let tombstoned_ids = self
            .core
            .storage
            .data
            .get_bitmap(BitmapKey {
                account_id,
                collection: Collection::Email.into(),
                class: BitmapClass::Tag {
                    field: Property::MailboxIds.into(),
                    value: TagValue::Id(TOMBSTONE_ID),
                },
                document_id: 0,
            })
            .await?
            .unwrap_or_default();

        if tombstoned_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::TombstoneCleanup),
            AccountId = account_id,
            Total = tombstoned_ids.len(),
        );

        // Delete threadIds
        self.emails_purge_threads(account_id).await?;

        // Delete full-text index
        self.core
            .storage
            .fts
            .remove(account_id, Collection::Email.into(), &tombstoned_ids)
            .await?;

        // Obtain tenant id
        let tenant_id = self
            .get_access_token(account_id)
            .await
            .caused_by(trc::location!())?
            .tenant
            .map(|t| t.id);

        // Delete messages
        for document_id in tombstoned_ids {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .delete_document(document_id)
                .clear(Property::Value)
                .untag(
                    Property::MailboxIds,
                    TagValue::Id(MaybeDynamicId::Static(TOMBSTONE_ID)),
                );

            // Remove message metadata
            if let Some(metadata_) = self
                .core
                .storage
                .data
                .get_value::<Archive<AlignedBytes>>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(Property::BodyStructure.into()),
                })
                .await?
            {
                let metadata = metadata_
                    .unarchive::<MessageMetadata>()
                    .caused_by(trc::location!())?;

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                // Hold blob for undeletion
                #[cfg(feature = "enterprise")]
                self.core.hold_undelete(
                    &mut batch,
                    Collection::Email.into(),
                    &BlobHash::from(&metadata.blob_hash),
                    u32::from(metadata.size) as usize,
                );

                // SPDX-SnippetEnd

                // Delete message
                metadata
                    .index(&mut batch, account_id, tenant_id, false)
                    .caused_by(trc::location!())?;

                // Commit batch
                self.core.storage.data.write(batch.build()).await?;
            } else {
                trc::event!(
                    Purge(trc::PurgeEvent::Error),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = "Failed to fetch message metadata.",
                    CausedBy = trc::location!(),
                );
            }
        }

        Ok(())
    }

    async fn emails_purge_threads(&self, account_id: u32) -> trc::Result<()> {
        // Delete threadIs without documents
        let mut thread_ids = self
            .get_document_ids(account_id, Collection::Thread)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();

        if thread_ids.is_empty() {
            return Ok(());
        }

        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    BitmapKey {
                        account_id,
                        collection: Collection::Email.into(),
                        class: BitmapClass::Tag {
                            field: Property::ThreadId.into(),
                            value: TagValue::Id(0),
                        },
                        document_id: 0,
                    },
                    BitmapKey {
                        account_id,
                        collection: Collection::Email.into(),
                        class: BitmapClass::Tag {
                            field: Property::ThreadId.into(),
                            value: TagValue::Id(u32::MAX),
                        },
                        document_id: u32::MAX,
                    },
                )
                .no_values(),
                |key, _| {
                    let (thread_id, _) = key
                        .get(U32_LEN + 2..)
                        .and_then(|bytes| bytes.read_leb128::<u32>())
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    thread_ids.remove(thread_id);

                    Ok(!thread_ids.is_empty())
                },
            )
            .await
            .caused_by(trc::location!())?;

        if thread_ids.is_empty() {
            return Ok(());
        }

        // Create batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Thread)
            .with_change_id(self.generate_snowflake_id().caused_by(trc::location!())?)
            .log(Changes::delete(thread_ids.iter().map(|id| id as u64)));
        for thread_id in thread_ids {
            batch.delete_document(thread_id);
        }
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }
}
