/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::metadata::MessageData;
use crate::{cache::MessageCacheFetch, mailbox::*, message::metadata::MessageMetadata};
use common::{KV_LOCK_PURGE_ACCOUNT, Server, storage::index::ObjectIndexBuilder};
use jmap_proto::types::collection::VanishedCollection;
use jmap_proto::types::{collection::Collection, property::Property};
use std::future::Future;
use std::time::Duration;
use store::rand::prelude::SliceRandom;
use store::write::key::DeserializeBigEndian;
use store::write::now;
use store::{
    BitmapKey, ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, BitmapClass, TagValue, ValueClass},
};
use store::{IndexKey, IterateParams, SerializeInfallible, U32_LEN};
use trc::AddContext;
use utils::BlobHash;

pub trait EmailDeletion: Sync + Send {
    fn emails_tombstone(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;

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
}

impl EmailDeletion for Server {
    async fn emails_tombstone(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        document_ids: RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        // Tombstone message and untag it from the mailboxes
        let mut deleted_ids = RoaringBitmap::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);
        self.get_archives(
            account_id,
            Collection::Email,
            &document_ids,
            |document_id, data_| {
                // Add changes to batch
                let metadata = data_
                    .to_unarchived::<MessageData>()
                    .caused_by(trc::location!())?;
                for mailbox in metadata.inner.mailboxes.iter() {
                    batch.log_vanished_item(
                        VanishedCollection::Email,
                        (mailbox.mailbox_id.to_native(), mailbox.uid.to_native()),
                    );
                }
                batch
                    .update_document(document_id)
                    .custom(ObjectIndexBuilder::<_, ()>::new().with_current(metadata))
                    .caused_by(trc::location!())?
                    .tag(Property::MailboxIds, TagValue::Id(TOMBSTONE_ID))
                    .commit_point();

                deleted_ids.insert(document_id);

                Ok(true)
            },
        )
        .await?;

        let not_destroyed = if document_ids.len() == deleted_ids.len() {
            RoaringBitmap::new()
        } else {
            deleted_ids ^= document_ids;
            deleted_ids
        };

        Ok(not_destroyed)
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
        let trashed_ids = RoaringBitmap::from_iter(
            self.get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?
                .emails
                .items
                .iter()
                .filter(|item| {
                    item.mailboxes
                        .iter()
                        .any(|id| id.mailbox_id == TRASH_ID || id.mailbox_id == JUNK_ID)
                })
                .map(|item| item.document_id),
        );
        if trashed_ids.is_empty() {
            return Ok(());
        }

        // Filter messages by received date
        let mut destroy_ids = RoaringBitmap::new();
        self.store()
            .iterate(
                IterateParams::new(
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        field: Property::ReceivedAt.into(),
                        key: 0u64.serialize(),
                    },
                    IndexKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        field: Property::ReceivedAt.into(),
                        key: now().saturating_sub(period.as_secs()).serialize(),
                    },
                )
                .no_values()
                .ascending(),
                |key, _| {
                    let document_id = key
                        .deserialize_be_u32(key.len() - U32_LEN)
                        .caused_by(trc::location!())?;

                    if trashed_ids.contains(document_id) {
                        destroy_ids.insert(document_id);
                    }

                    Ok(trashed_ids.len() != destroy_ids.len())
                },
            )
            .await
            .caused_by(trc::location!())?;

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Tombstone messages
        let mut batch = BatchBuilder::new();
        self.emails_tombstone(account_id, &mut batch, destroy_ids)
            .await?;
        self.commit_batch(batch).await?;

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
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        for document_id in tombstoned_ids {
            batch
                .with_collection(Collection::Email)
                .delete_document(document_id)
                .clear(Property::Value)
                .untag(Property::MailboxIds, TagValue::Id(TOMBSTONE_ID));

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
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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

                // Commit point
                batch.commit_point();
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

        self.commit_batch(batch).await?;

        Ok(())
    }
}
