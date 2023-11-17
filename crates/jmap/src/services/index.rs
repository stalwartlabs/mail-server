/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    fts::index::FtsDocument,
    write::{BatchBuilder, ValueClass},
    IterateParams, ValueKey,
};

use crate::{
    email::{index::IndexMessageText, metadata::MessageMetadata},
    Bincode, NamedKey, JMAP,
};

use super::housekeeper::Event;

impl JMAP {
    pub async fn fts_index_queued(&self) {
        let from_key = ValueKey::<ValueClass> {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: NamedKey::IndexEmail::<&[u8]> {
                account_id: 0,
                document_id: 0,
                seq: 0,
            }
            .into(),
        };
        let to_key = ValueKey::<ValueClass> {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: NamedKey::IndexEmail::<&[u8]> {
                account_id: u32::MAX,
                document_id: u32::MAX,
                seq: u64::MAX,
            }
            .into(),
        };

        // Retrieve entries pending to be indexed
        // TODO: Support indexing from multiple nodes
        let mut entries = Vec::new();
        let _ = self
            .store
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    entries.push((
                        NamedKey::<Vec<u8>>::deserialize_index_email(key)?,
                        value.to_vec(),
                    ));
                    Ok(true)
                },
            )
            .await
            .map_err(|err| {
                tracing::error!(
                    context = "fts_index_queued",
                    event = "error",
                    reason = ?err,
                    "Failed to iterate over index emails"
                );
            });

        // Index entries
        for (key, blob_hash) in entries {
            if let NamedKey::IndexEmail {
                account_id,
                document_id,
                ..
            } = &key
            {
                if !blob_hash.is_empty() {
                    match self
                        .get_property::<Bincode<MessageMetadata>>(
                            *account_id,
                            Collection::Email,
                            *document_id,
                            Property::BodyStructure,
                        )
                        .await
                    {
                        Ok(Some(metadata))
                            if metadata.inner.blob_hash.as_slice() == blob_hash.as_slice() =>
                        {
                            // Obtain raw message
                            let raw_message = if let Ok(Some(raw_message)) =
                                self.get_blob(&metadata.inner.blob_hash, 0..u32::MAX).await
                            {
                                raw_message
                            } else {
                                tracing::warn!(
                                    context = "fts_index_queued",
                                    event = "error",
                                    account_id = *account_id,
                                    document_id = *document_id,
                                    blob_hash = ?metadata.inner.blob_hash,
                                    "Message blob not found"
                                );
                                continue;
                            };
                            let message = metadata.inner.contents.into_message(&raw_message);

                            // Index message
                            let document =
                                FtsDocument::with_default_language(self.config.default_language)
                                    .with_account_id(*account_id)
                                    .with_collection(Collection::Email)
                                    .with_document_id(*document_id)
                                    .index_message(&message);
                            if let Err(err) = self.fts_store.index(document).await {
                                tracing::error!(
                                    context = "fts_index_queued",
                                    event = "error",
                                    account_id = *account_id,
                                    document_id = *document_id,
                                    reason = ?err,
                                    "Failed to index email in FTS index"
                                );
                                continue;
                            }

                            tracing::debug!(
                                context = "fts_index_queued",
                                event = "index",
                                account_id = *account_id,
                                document_id = *document_id,
                                "Indexed document in FTS index"
                            );
                        }

                        Err(err) => {
                            tracing::error!(
                                context = "fts_index_queued",
                                event = "error",
                                account_id = *account_id,
                                document_id = *document_id,
                                reason = ?err,
                                "Failed to retrieve email metadata"
                            );
                            break;
                        }
                        _ => {
                            // The message was probably deleted or overwritten
                            tracing::debug!(
                                context = "fts_index_queued",
                                event = "error",
                                account_id = *account_id,
                                document_id = *document_id,
                                "Email metadata not found"
                            );
                        }
                    }
                } else {
                    if let Err(err) = self
                        .fts_store
                        .remove(*account_id, Collection::Email.into(), *document_id)
                        .await
                    {
                        tracing::error!(
                            context = "fts_index_queued",
                            event = "error",
                            account_id = *account_id,
                            document_id = *document_id,
                            reason = ?err,
                            "Failed to remove document from FTS index"
                        );
                        continue;
                    }

                    tracing::debug!(
                        context = "fts_index_queued",
                        event = "delete",
                        account_id = *account_id,
                        document_id = *document_id,
                        "Deleted document from FTS index"
                    );
                }
            }

            // Remove entry from queue
            if let Err(err) = self
                .store
                .write(BatchBuilder::new().clear(key).build_batch())
                .await
            {
                tracing::error!(
                    context = "fts_index_queued",
                    event = "error",
                    reason = ?err,
                    "Failed to remove index email from queue"
                );
                break;
            }
        }

        if let Err(err) = self.housekeeper_tx.send(Event::IndexDone).await {
            tracing::warn!("Failed to send index done event to housekeeper: {}", err);
        }
    }
}
