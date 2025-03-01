/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use common::{Inner, KV_LOCK_EMAIL_TASK, Server, core::BuildServer};
use directory::{
    Type,
    backend::internal::{PrincipalField, manage::ManageDirectory},
};
use email::message::{bayes::EmailBayesTrain, index::IndexMessageText, metadata::MessageMetadata};
use jmap_proto::types::{collection::Collection, property::Property};
use mail_parser::MessageParser;
use store::{
    IterateParams, SerializeInfallible, U32_LEN, U64_LEN, ValueKey,
    ahash::AHashMap,
    fts::index::FtsDocument,
    roaring::RoaringBitmap,
    write::{
        Archive, BatchBuilder, BlobOp, MaybeDynamicId, TaskQueueClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};

use std::future::Future;
use trc::{AddContext, TaskQueueEvent};
use utils::{BLOB_HASH_LEN, BlobHash};

use crate::blob::download::BlobDownload;

#[derive(Debug, Clone)]
pub struct EmailTask {
    account_id: u32,
    document_id: u32,
    seq: u64,
    hash: BlobHash,
    action: EmailTaskAction,
}

#[derive(Debug, Clone, Copy)]
pub enum EmailTaskAction {
    Index,
    BayesTrain { learn_spam: bool },
}

const FTS_LOCK_EXPIRY: u64 = 60 * 5;
const BAYES_LOCK_EXPIRY: u64 = 60 * 30;

pub fn spawn_email_queue_task(inner: Arc<Inner>) {
    tokio::spawn(async move {
        let rx = inner.ipc.index_tx.clone();
        let mut locked_seq_ids = AHashMap::new();
        loop {
            // Index any queued messages
            inner
                .build_server()
                .email_task_queued(&mut locked_seq_ids)
                .await;

            // Wait for a signal to index more messages
            rx.notified().await;
        }
    });
}

pub trait Indexer: Sync + Send {
    fn email_task_queued(
        &self,
        locked_seq_ids: &mut AHashMap<u64, Instant>,
    ) -> impl Future<Output = ()> + Send;
    fn try_lock_index(&self, event: &EmailTask) -> impl Future<Output = bool> + Send;
    fn remove_index_lock(&self, event: &EmailTask) -> impl Future<Output = ()> + Send;
    fn reindex(
        &self,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl Indexer for Server {
    async fn email_task_queued(&self, locked_seq_ids: &mut AHashMap<u64, Instant>) {
        let from_key = ValueKey::<ValueClass<u32>> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                seq: 0,
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey::<ValueClass<u32>> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                seq: u64::MAX,
                hash: BlobHash::default(),
            }),
        };

        // Retrieve entries pending to be indexed
        let mut entries = Vec::new();
        let now = Instant::now();
        let _ = self
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let entry = EmailTask::deserialize(key)?;
                    if locked_seq_ids
                        .get(&entry.seq)
                        .is_none_or(|expires| now >= *expires)
                    {
                        entries.push(entry);
                    }

                    Ok(true)
                },
            )
            .await
            .map_err(|err| {
                trc::error!(
                    err.caused_by(trc::location!())
                        .details("Failed to iterate over index emails")
                );
            });

        // Add entries to the index
        let mut unlock_events = Vec::with_capacity(entries.len());
        for event in entries {
            let op_start = Instant::now();
            // Lock index
            if !self.try_lock_index(&event).await {
                locked_seq_ids.insert(
                    event.seq,
                    Instant::now() + std::time::Duration::from_secs(event.lock_expiry() + 1),
                );
                continue;
            }

            if event.remove_lock() {
                unlock_events.push(event.clone());
            }

            // Obtain raw message
            let raw_message =
                if let Ok(Some(raw_message)) = self.get_blob(&event.hash, 0..usize::MAX).await {
                    raw_message
                } else {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::BlobNotFound),
                        AccountId = event.account_id,
                        DocumentId = event.document_id,
                        BlobId = event.hash.as_slice(),
                    );
                    continue;
                };

            match event.action {
                EmailTaskAction::Index => {
                    match self
                        .get_property::<Archive>(
                            event.account_id,
                            Collection::Email,
                            event.document_id,
                            Property::BodyStructure,
                        )
                        .await
                    {
                        Ok(Some(metadata_)) => {
                            match metadata_.unarchive::<MessageMetadata>() {
                                Ok(metadata)
                                    if metadata.blob_hash.0.as_slice() == event.hash.as_slice() =>
                                {
                                    // Index message
                                    let document = FtsDocument::with_default_language(
                                        self.core.jmap.default_language,
                                    )
                                    .with_account_id(event.account_id)
                                    .with_collection(Collection::Email)
                                    .with_document_id(event.document_id)
                                    .index_message(metadata, &raw_message);
                                    if let Err(err) = self.core.storage.fts.index(document).await {
                                        trc::error!(
                                            err.account_id(event.account_id)
                                                .document_id(event.document_id)
                                                .details("Failed to index email in FTS index")
                                        );

                                        continue;
                                    }

                                    trc::event!(
                                        TaskQueue(TaskQueueEvent::Index),
                                        AccountId = event.account_id,
                                        Collection = Collection::Email,
                                        DocumentId = event.document_id,
                                        Elapsed = op_start.elapsed(),
                                    );
                                }
                                Err(err) => {
                                    trc::error!(
                                        err.account_id(event.account_id)
                                            .document_id(event.document_id)
                                            .details("Failed to unarchive email metadata")
                                    );
                                }

                                _ => {
                                    // The message was probably deleted or overwritten
                                    trc::event!(
                                        TaskQueue(TaskQueueEvent::MetadataNotFound),
                                        Details = "Blob hash mismatch",
                                        AccountId = event.account_id,
                                        DocumentId = event.document_id,
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            trc::error!(
                                err.account_id(event.account_id)
                                    .document_id(event.document_id)
                                    .caused_by(trc::location!())
                                    .details("Failed to retrieve email metadata")
                            );

                            continue;
                        }
                        _ => {
                            // The message was probably deleted or overwritten
                            trc::event!(
                                TaskQueue(TaskQueueEvent::MetadataNotFound),
                                AccountId = event.account_id,
                                DocumentId = event.document_id,
                            );
                        }
                    }
                }
                EmailTaskAction::BayesTrain { learn_spam } => {
                    // Train bayes classifier for account
                    self.email_bayes_train(
                        event.account_id,
                        0,
                        MessageParser::new().parse(&raw_message).unwrap_or_default(),
                        learn_spam,
                    )
                    .await;

                    trc::event!(
                        TaskQueue(TaskQueueEvent::BayesTrain),
                        AccountId = event.account_id,
                        Collection = Collection::Email,
                        DocumentId = event.document_id,
                        Elapsed = op_start.elapsed(),
                    );
                }
            }

            // Remove entry from queue
            if let Err(err) = self
                .core
                .storage
                .data
                .write(
                    BatchBuilder::new()
                        .with_account_id(event.account_id)
                        .with_collection(Collection::Email)
                        .update_document(event.document_id)
                        .clear(event.value_class())
                        .build_batch(),
                )
                .await
            {
                trc::error!(
                    err.account_id(event.account_id)
                        .document_id(event.document_id)
                        .details("Failed to remove index email from queue.")
                );
            }
        }

        // Unlock entries
        for event in unlock_events {
            self.remove_index_lock(&event).await;
        }

        // Delete expired locks
        let now = Instant::now();
        locked_seq_ids.retain(|_, expires| *expires > now);
    }

    async fn try_lock_index(&self, event: &EmailTask) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_EMAIL_TASK, &event.lock_key(), event.lock_expiry())
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        TaskQueue(TaskQueueEvent::Locked),
                        AccountId = event.account_id,
                        DocumentId = event.document_id,
                        Expires = trc::Value::Timestamp(now() + event.lock_expiry()),
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.account_id(event.account_id)
                        .document_id(event.document_id)
                        .details("Failed to lock email task")
                );

                false
            }
        }
    }

    async fn remove_index_lock(&self, event: &EmailTask) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_EMAIL_TASK, &event.lock_key())
            .await
        {
            trc::error!(
                err.details("Failed to unlock email task")
                    .ctx(trc::Key::Key, event.seq)
                    .caused_by(trc::location!())
            );
        }
    }

    async fn reindex(&self, account_id: Option<u32>, tenant_id: Option<u32>) -> trc::Result<()> {
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
                    &[PrincipalField::Name],
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

        let mut seq = self.generate_snowflake_id().caused_by(trc::location!())?;

        for (account_id, hashes) in hashes {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email);

            for (document_id, hash) in hashes {
                batch.update_document(document_id).set(
                    ValueClass::TaskQueue(TaskQueueClass::IndexEmail { hash, seq }),
                    0u64.serialize(),
                );
                seq += 1;

                if batch.ops.len() >= 2000 {
                    self.core.storage.data.write(batch.build()).await?;
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email);
                }
            }

            if !batch.is_empty() {
                self.core.storage.data.write(batch.build()).await?;
            }
        }

        // Request indexing
        self.notify_task_queue();

        Ok(())
    }
}

impl EmailTask {
    fn remove_lock(&self) -> bool {
        matches!(self.action, EmailTaskAction::Index)
    }

    fn lock_key(&self) -> Vec<u8> {
        match self.action {
            EmailTaskAction::Index => KeySerializer::new(U64_LEN + 1)
                .write(0u8)
                .write(self.seq)
                .finalize(),
            EmailTaskAction::BayesTrain { .. } => KeySerializer::new((U32_LEN * 2) + 1)
                .write(1u8)
                .write_leb128(self.account_id)
                .write_leb128(self.document_id)
                .finalize(),
        }
    }

    fn lock_expiry(&self) -> u64 {
        match self.action {
            EmailTaskAction::Index => FTS_LOCK_EXPIRY,
            EmailTaskAction::BayesTrain { .. } => BAYES_LOCK_EXPIRY,
        }
    }

    fn value_class(&self) -> ValueClass<MaybeDynamicId> {
        ValueClass::TaskQueue(match self.action {
            EmailTaskAction::Index => TaskQueueClass::IndexEmail {
                hash: self.hash.clone(),
                seq: self.seq,
            },
            EmailTaskAction::BayesTrain { learn_spam } => TaskQueueClass::BayesTrain {
                hash: self.hash.clone(),
                seq: self.seq,
                learn_spam,
            },
        })
    }

    fn deserialize(key: &[u8]) -> trc::Result<Self> {
        Ok(EmailTask {
            seq: key.deserialize_be_u64(0)?,
            account_id: key.deserialize_be_u32(U64_LEN)?,
            document_id: key.deserialize_be_u32(U64_LEN + U32_LEN + 1)?,
            action: match key.get(U64_LEN + U32_LEN) {
                Some(0) => EmailTaskAction::Index,
                Some(1) => EmailTaskAction::BayesTrain { learn_spam: true },
                Some(2) => EmailTaskAction::BayesTrain { learn_spam: false },
                _ => return Err(trc::Error::corrupted_key(key, None, trc::location!())),
            },
            hash: key
                .get(
                    U64_LEN + U32_LEN + U32_LEN + 1
                        ..U64_LEN + U32_LEN + U32_LEN + BLOB_HASH_LEN + 1,
                )
                .and_then(|bytes| BlobHash::try_from_hash_slice(bytes).ok())
                .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
        })
    }
}
