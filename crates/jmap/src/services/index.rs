/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    fts::index::FtsDocument,
    write::{
        key::DeserializeBigEndian, now, BatchBuilder, Bincode, FtsQueueClass, MaybeDynamicId,
        ValueClass,
    },
    Deserialize, IterateParams, Serialize, ValueKey, U32_LEN, U64_LEN,
};

use trc::FtsIndexEvent;
use utils::{BlobHash, BLOB_HASH_LEN};

use crate::{
    email::{index::IndexMessageText, metadata::MessageMetadata},
    JMAP,
};

use super::housekeeper::Event;

#[derive(Debug)]
struct IndexEmail {
    account_id: u32,
    document_id: u32,
    seq: u64,
    lock_expiry: u64,
    insert_hash: BlobHash,
}

const INDEX_LOCK_EXPIRY: u64 = 60 * 5;

impl JMAP {
    pub async fn fts_index_queued(&self) {
        let from_key = ValueKey::<ValueClass<u32>> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::FtsQueue(FtsQueueClass {
                seq: 0,
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey::<ValueClass<u32>> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::FtsQueue(FtsQueueClass {
                seq: u64::MAX,
                hash: BlobHash::default(),
            }),
        };

        // Retrieve entries pending to be indexed
        let mut entries = Vec::new();
        let now = now();
        let _ = self
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let event = IndexEmail::deserialize(key, value)?;

                    if event.lock_expiry < now {
                        entries.push(event);
                    } else {
                        trc::event!(
                            FtsIndex(FtsIndexEvent::Locked),
                            AccountId = event.account_id,
                            DocumentId = event.document_id,
                            Expires = trc::Value::Timestamp(event.lock_expiry),
                        );
                    }

                    Ok(true)
                },
            )
            .await
            .map_err(|err| {
                trc::error!(err.details("Failed to iterate over index emails"));
            });

        // Add entries to the index
        for event in entries {
            let op_start = Instant::now();
            // Lock index
            if !self.try_lock_index(&event).await {
                continue;
            }

            match self
                .get_property::<Bincode<MessageMetadata>>(
                    event.account_id,
                    Collection::Email,
                    event.document_id,
                    Property::BodyStructure,
                )
                .await
            {
                Ok(Some(metadata))
                    if metadata.inner.blob_hash.as_slice() == event.insert_hash.as_slice() =>
                {
                    // Obtain raw message
                    let raw_message = if let Ok(Some(raw_message)) = self
                        .get_blob(&metadata.inner.blob_hash, 0..usize::MAX)
                        .await
                    {
                        raw_message
                    } else {
                        trc::event!(
                            FtsIndex(FtsIndexEvent::BlobNotFound),
                            AccountId = event.account_id,
                            DocumentId = event.document_id,
                            BlobId = metadata.inner.blob_hash.to_hex(),
                        );
                        continue;
                    };
                    let message = metadata.inner.contents.into_message(&raw_message);

                    // Index message
                    let document =
                        FtsDocument::with_default_language(self.core.jmap.default_language)
                            .with_account_id(event.account_id)
                            .with_collection(Collection::Email)
                            .with_document_id(event.document_id)
                            .index_message(&message);
                    if let Err(err) = self.core.storage.fts.index(document).await {
                        trc::error!(err
                            .account_id(event.account_id)
                            .document_id(event.document_id)
                            .details("Failed to index email in FTS index"));

                        continue;
                    }

                    trc::event!(
                        FtsIndex(FtsIndexEvent::Index),
                        AccountId = event.account_id,
                        Collection = Collection::Email,
                        DocumentId = event.document_id,
                        Elapsed = op_start.elapsed(),
                    );
                }

                Err(err) => {
                    trc::error!(err
                        .account_id(event.account_id)
                        .document_id(event.document_id)
                        .caused_by(trc::location!())
                        .details("Failed to retrieve email metadata"));

                    break;
                }
                _ => {
                    // The message was probably deleted or overwritten
                    trc::event!(
                        FtsIndex(FtsIndexEvent::MetadataNotFound),
                        AccountId = event.account_id,
                        DocumentId = event.document_id,
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
                trc::error!(err
                    .account_id(event.account_id)
                    .document_id(event.document_id)
                    .details("Failed to remove index email from queue."));

                break;
            }
        }

        if self
            .inner
            .housekeeper_tx
            .send(Event::IndexDone)
            .await
            .is_err()
        {
            trc::event!(
                Server(trc::ServerEvent::ThreadError),
                Details = "Failed to send event to Housekeeper",
                CausedBy = trc::location!()
            );
        }
    }

    async fn try_lock_index(&self, event: &IndexEmail) -> bool {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(event.account_id)
            .with_collection(Collection::Email)
            .update_document(event.document_id)
            .assert_value(event.value_class(), event.lock_expiry)
            .set(event.value_class(), (now() + INDEX_LOCK_EXPIRY).serialize());
        match self.core.storage.data.write(batch.build()).await {
            Ok(_) => true,
            Err(err) if err.is_assertion_failure() => {
                trc::event!(
                    FtsIndex(FtsIndexEvent::LockBusy),
                    AccountId = event.account_id,
                    DocumentId = event.document_id,
                    CausedBy = err,
                );

                false
            }
            Err(err) => {
                trc::error!(err
                    .account_id(event.account_id)
                    .document_id(event.document_id)
                    .details("Failed to lock FTS index"));

                false
            }
        }
    }
}

impl IndexEmail {
    fn value_class(&self) -> ValueClass<MaybeDynamicId> {
        ValueClass::FtsQueue(FtsQueueClass {
            hash: self.insert_hash.clone(),
            seq: self.seq,
        })
    }

    fn deserialize(key: &[u8], value: &[u8]) -> trc::Result<Self> {
        Ok(IndexEmail {
            seq: key.deserialize_be_u64(0)?,
            account_id: key.deserialize_be_u32(U64_LEN)?,
            document_id: key.deserialize_be_u32(U64_LEN + U32_LEN + 1)?,
            lock_expiry: u64::deserialize(value)?,
            insert_hash: key
                .get(
                    U64_LEN + U32_LEN + U32_LEN + 1
                        ..U64_LEN + U32_LEN + U32_LEN + BLOB_HASH_LEN + 1,
                )
                .and_then(|bytes| BlobHash::try_from_hash_slice(bytes).ok())
                .ok_or_else(|| trc::Error::corrupted_key(key, value.into(), trc::location!()))?,
        })
    }
}
