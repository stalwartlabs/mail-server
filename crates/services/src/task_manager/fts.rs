/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::Server;
use directory::{Type, backend::internal::manage::ManageDirectory};
use email::message::{index::IndexMessageText, metadata::MessageMetadata};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    ahash::AHashMap,
    fts::index::FtsDocument,
    roaring::RoaringBitmap,
    write::{BatchBuilder, BlobOp, TaskQueueClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::{AddContext, MessageIngestEvent, TaskQueueEvent};
use utils::{BLOB_HASH_LEN, BlobHash};

use super::Task;

pub trait FtsIndexTask: Sync + Send {
    fn fts_index(&self, task: &Task, hash: &BlobHash) -> impl Future<Output = bool> + Send;
    fn fts_reindex(
        &self,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl FtsIndexTask for Server {
    async fn fts_index(&self, task: &Task, hash: &BlobHash) -> bool {
        // Obtain raw message
        let op_start = Instant::now();
        let raw_message = if let Ok(Some(raw_message)) = self
            .blob_store()
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
        {
            raw_message
        } else {
            trc::event!(
                TaskQueue(TaskQueueEvent::BlobNotFound),
                AccountId = task.account_id,
                DocumentId = task.document_id,
                BlobId = hash.as_slice(),
            );
            return false;
        };

        match self
            .get_archive_by_property(
                task.account_id,
                Collection::Email,
                task.document_id,
                Property::BodyStructure,
            )
            .await
        {
            Ok(Some(metadata_)) => {
                match metadata_.unarchive::<MessageMetadata>() {
                    Ok(metadata) if metadata.blob_hash.0.as_slice() == hash.as_slice() => {
                        // Index message
                        let document =
                            FtsDocument::with_default_language(self.core.jmap.default_language)
                                .with_account_id(task.account_id)
                                .with_collection(Collection::Email)
                                .with_document_id(task.document_id)
                                .index_message(metadata, &raw_message);
                        if let Err(err) = self.core.storage.fts.index(document).await {
                            trc::error!(
                                err.account_id(task.account_id)
                                    .document_id(task.document_id)
                                    .details("Failed to index email in FTS index")
                            );

                            return false;
                        }

                        trc::event!(
                            MessageIngest(MessageIngestEvent::FtsIndex),
                            AccountId = task.account_id,
                            Collection = Collection::Email,
                            DocumentId = task.document_id,
                            Elapsed = op_start.elapsed(),
                        );
                    }
                    Err(err) => {
                        trc::error!(
                            err.account_id(task.account_id)
                                .document_id(task.document_id)
                                .details("Failed to unarchive email metadata")
                        );
                    }

                    _ => {
                        // The message was probably deleted or overwritten
                        trc::event!(
                            TaskQueue(TaskQueueEvent::MetadataNotFound),
                            Details = "E-mail blob hash mismatch",
                            AccountId = task.account_id,
                            DocumentId = task.document_id,
                        );
                    }
                }

                true
            }
            Err(err) => {
                trc::error!(
                    err.account_id(task.account_id)
                        .document_id(task.document_id)
                        .caused_by(trc::location!())
                        .details("Failed to retrieve email metadata")
                );

                false
            }
            _ => {
                // The message was probably deleted or overwritten
                trc::event!(
                    TaskQueue(TaskQueueEvent::MetadataNotFound),
                    Details = "E-mail metadata not found",
                    AccountId = task.account_id,
                    DocumentId = task.document_id,
                );
                true
            }
        }
    }

    async fn fts_reindex(
        &self,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> trc::Result<()> {
        let accounts = if let Some(account_id) = account_id {
            RoaringBitmap::from_sorted_iter([account_id]).unwrap()
        } else {
            let mut accounts = RoaringBitmap::new();
            for principal in self
                .core
                .storage
                .data
                .list_principals(
                    None,
                    tenant_id,
                    &[Type::Individual, Type::Group],
                    false,
                    0,
                    0,
                )
                .await
                .caused_by(trc::location!())?
                .items
            {
                accounts.insert(principal.id());
            }
            accounts
        };

        // Validate linked blobs
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Link {
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Link {
                hash: BlobHash::new_max(),
            }),
        };
        let mut hashes: AHashMap<u32, Vec<(u32, BlobHash)>> = AHashMap::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                    let collection = *key
                        .get(BLOB_HASH_LEN + U32_LEN)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                    if accounts.contains(account_id) && collection == Collection::Email as u8 {
                        let hash =
                            BlobHash::try_from_hash_slice(key.get(0..BLOB_HASH_LEN).ok_or_else(
                                || trc::Error::corrupted_key(key, None, trc::location!()),
                            )?)
                            .unwrap();
                        let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;

                        hashes
                            .entry(account_id)
                            .or_default()
                            .push((document_id, hash));
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let due = now();

        for (account_id, hashes) in hashes {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email);

            for (document_id, hash) in hashes {
                batch.update_document(document_id).set(
                    ValueClass::TaskQueue(TaskQueueClass::IndexEmail { hash, due }),
                    0u64.serialize(),
                );

                if batch.len() >= 2000 {
                    self.core.storage.data.write(batch.build_all()).await?;
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email);
                }
            }

            if !batch.is_empty() {
                self.core.storage.data.write(batch.build_all()).await?;
            }
        }

        // Request indexing
        self.notify_task_queue();

        Ok(())
    }
}
