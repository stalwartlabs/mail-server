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

use std::borrow::Cow;

use jmap_proto::{
    object::Object,
    types::{
        blob::BlobId, collection::Collection, id::Id, keyword::Keyword, property::Property,
        value::Value,
    },
};
use mail_parser::{
    parsers::fields::thread::thread_name, HeaderName, HeaderValue, Message, PartType,
};

use store::{
    ahash::AHashSet,
    query::Filter,
    write::{
        log::ChangeLogBuilder, now, BatchBuilder, BitmapClass, TagValue, ValueClass, F_BITMAP,
        F_CLEAR, F_VALUE,
    },
    BitmapKey, BlobClass, ValueKey,
};
use utils::map::vec_map::VecMap;

use crate::{
    email::index::{IndexMessage, MAX_ID_LENGTH},
    mailbox::UidMailbox,
    services::housekeeper::Event,
    IngestError, NamedKey, JMAP,
};

use super::{
    crypto::{EncryptMessage, EncryptMessageError, EncryptionParams},
    index::{TrimTextValue, MAX_SORT_FIELD_LENGTH},
};

#[derive(Default)]
pub struct IngestedEmail {
    pub id: Id,
    pub change_id: u64,
    pub blob_id: BlobId,
    pub size: usize,
}

pub struct IngestEmail<'x> {
    pub raw_message: &'x [u8],
    pub message: Option<Message<'x>>,
    pub account_id: u32,
    pub account_quota: i64,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub skip_duplicates: bool,
    pub encrypt: bool,
}

impl JMAP {
    #[allow(clippy::blocks_in_if_conditions)]
    pub async fn email_ingest(
        &self,
        params: IngestEmail<'_>,
    ) -> Result<IngestedEmail, IngestError> {
        // Check quota
        let mut raw_message_len = params.raw_message.len() as i64;
        if params.account_quota > 0
            && raw_message_len
                + self
                    .get_used_quota(params.account_id)
                    .await
                    .map_err(|_| IngestError::Temporary)?
                > params.account_quota
        {
            return Err(IngestError::OverQuota);
        }

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.ok_or_else(|| IngestError::Permanent {
            code: [5, 5, 0],
            reason: "Failed to parse e-mail message.".to_string(),
        })?;

        // Obtain message references and thread name
        let thread_id = {
            let mut references = Vec::with_capacity(5);
            let mut subject = "";
            for header in message.root_part().headers().iter().rev() {
                match header.name {
                    HeaderName::MessageId
                    | HeaderName::InReplyTo
                    | HeaderName::References
                    | HeaderName::ResentMessageId => match &header.value {
                        HeaderValue::Text(id) if id.len() < MAX_ID_LENGTH => {
                            references.push(id.as_ref());
                        }
                        HeaderValue::TextList(ids) => {
                            for id in ids {
                                if id.len() < MAX_ID_LENGTH {
                                    references.push(id.as_ref());
                                }
                            }
                        }
                        _ => (),
                    },
                    HeaderName::Subject if subject.is_empty() => {
                        subject = thread_name(match &header.value {
                            HeaderValue::Text(text) => text.as_ref(),
                            HeaderValue::TextList(list) if !list.is_empty() => {
                                list.first().unwrap().as_ref()
                            }
                            _ => "",
                        })
                        .trim_text(MAX_SORT_FIELD_LENGTH);
                    }
                    _ => (),
                }
            }

            // Check for duplicates
            if params.skip_duplicates
                && !references.is_empty()
                && !self
                    .store
                    .filter(
                        params.account_id,
                        Collection::Email,
                        references
                            .iter()
                            .map(|id| Filter::eq(Property::MessageId, *id))
                            .collect(),
                    )
                    .await
                    .map_err(|err| {
                        tracing::error!(
                        event = "error",
                        context = "find_duplicates",
                        error = ?err,
                        "Duplicate message search failed.");
                        IngestError::Temporary
                    })?
                    .results
                    .is_empty()
            {
                return Ok(IngestedEmail {
                    id: Id::default(),
                    change_id: u64::MAX,
                    blob_id: BlobId::default(),
                    size: 0,
                });
            }

            if !references.is_empty() {
                self.find_or_merge_thread(params.account_id, subject, &references)
                    .await?
            } else {
                None
            }
        };

        // Encrypt message
        if params.encrypt && !message.is_encrypted() {
            if let Some(encrypt_params) = self
                .get_property::<EncryptionParams>(
                    params.account_id,
                    Collection::Principal,
                    0,
                    Property::Parameters,
                )
                .await
                .map_err(|_| IngestError::Temporary)?
            {
                match message.encrypt(&encrypt_params).await {
                    Ok(new_raw_message) => {
                        raw_message = Cow::from(new_raw_message);
                        raw_message_len = raw_message.len() as i64;

                        // Remove contents from parsed message
                        for part in &mut message.parts {
                            match &mut part.body {
                                PartType::Text(txt) | PartType::Html(txt) => {
                                    *txt = Cow::from("");
                                }
                                PartType::Binary(bin) | PartType::InlineBinary(bin) => {
                                    *bin = Cow::from(&[][..]);
                                }
                                PartType::Message(_) => {
                                    part.body = PartType::Binary(Cow::from(&[][..]));
                                }
                                PartType::Multipart(_) => (),
                            }
                        }
                    }
                    Err(EncryptMessageError::Error(err)) => {
                        tracing::error!(
                            event = "error",
                            context = "email_ingest",
                            error = ?err,
                            "Failed to encrypt message.");
                        return Err(IngestError::Temporary);
                    }
                    _ => unreachable!(),
                }
            }
        }

        // Obtain a documentId and changeId
        let document_id = self
            .store
            .assign_document_id(params.account_id, Collection::Email)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "email_ingest",
                    error = ?err,
                    "Failed to assign documentId.");
                IngestError::Temporary
            })?;
        let change_id = self
            .assign_change_id(params.account_id)
            .await
            .map_err(|_| {
                tracing::error!(
                    event = "error",
                    context = "email_ingest",
                    "Failed to assign changeId."
                );
                IngestError::Temporary
            })?;

        // Store blob
        let blob_id = self
            .put_blob(params.account_id, raw_message.as_ref(), false)
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "email_ingest",
                error = ?err,
                "Failed to write blob.");
                IngestError::Temporary
            })?;

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch.with_account_id(params.account_id);

        // Build change log
        let mut changes = ChangeLogBuilder::with_change_id(change_id);
        let thread_id = if let Some(thread_id) = thread_id {
            changes.log_child_update(Collection::Thread, thread_id);
            thread_id
        } else {
            let thread_id = self
                .store
                .assign_document_id(params.account_id, Collection::Thread)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "email_ingest",
                        error = ?err,
                        "Failed to assign documentId for new thread.");
                    IngestError::Temporary
                })?;
            batch
                .with_collection(Collection::Thread)
                .create_document(thread_id);
            changes.log_insert(Collection::Thread, thread_id);
            thread_id
        };
        let id = Id::from_parts(thread_id, document_id);
        changes.log_insert(Collection::Email, id);
        for mailbox_id in &params.mailbox_ids {
            changes.log_child_update(Collection::Mailbox, *mailbox_id);
        }

        // Build write batch
        batch
            .with_collection(Collection::Email)
            .create_document(document_id)
            .index_message(
                message,
                blob_id.hash.clone(),
                params.keywords,
                params
                    .mailbox_ids
                    .into_iter()
                    .map(UidMailbox::from)
                    .collect(),
                params.received_at.unwrap_or_else(now),
            )
            .value(Property::Cid, change_id, F_VALUE)
            .value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP)
            .custom(changes)
            .set(
                NamedKey::IndexEmail::<&[u8]> {
                    account_id: params.account_id,
                    document_id,
                    seq: self
                        .generate_snowflake_id()
                        .map_err(|_| IngestError::Temporary)?,
                },
                blob_id.hash.clone(),
            );
        self.store.write(batch.build()).await.map_err(|err| {
            tracing::error!(
                event = "error",
                context = "email_ingest",
                error = ?err,
                "Failed to write message to database.");
            IngestError::Temporary
        })?;

        // Request FTS index
        let _ = self.housekeeper_tx.send(Event::IndexStart).await;

        Ok(IngestedEmail {
            id,
            change_id,
            blob_id: BlobId {
                hash: blob_id.hash,
                class: BlobClass::Linked {
                    account_id: params.account_id,
                    collection: Collection::Email.into(),
                    document_id,
                },
                section: blob_id.section,
            },
            size: raw_message_len as usize,
        })
    }

    pub async fn find_or_merge_thread(
        &self,
        account_id: u32,
        thread_name: &str,
        references: &[&str],
    ) -> Result<Option<u32>, IngestError> {
        let mut try_count = 0;

        loop {
            // Find messages with matching references
            let mut filters = Vec::with_capacity(references.len() + 3);
            filters.push(Filter::eq(
                Property::Subject,
                if !thread_name.is_empty() {
                    thread_name
                } else {
                    "!"
                },
            ));
            filters.push(Filter::Or);
            for reference in references {
                filters.push(Filter::eq(Property::MessageId, *reference));
            }
            filters.push(Filter::End);
            let results = self
                .store
                .filter(account_id, Collection::Email, filters)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "find_or_merge_thread",
                        error = ?err,
                        "Thread search failed.");
                    IngestError::Temporary
                })?
                .results;

            if results.is_empty() {
                return Ok(None);
            }

            // Obtain threadIds for matching messages
            let thread_ids = self
                .store
                .get_values::<u32>(
                    results
                        .iter()
                        .map(|document_id| ValueKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id,
                            class: ValueClass::Property(Property::ThreadId.into()),
                        })
                        .collect(),
                )
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "find_or_merge_thread",
                        error = ?err,
                        "Failed to obtain threadIds.");
                    IngestError::Temporary
                })?;

            if thread_ids.len() == 1 {
                return Ok(thread_ids.into_iter().next().unwrap());
            }

            // Find the most common threadId
            let mut thread_counts = VecMap::<u32, u32>::with_capacity(thread_ids.len());
            let mut thread_id = u32::MAX;
            let mut thread_count = 0;
            for thread_id_ in thread_ids.iter().flatten() {
                let tc = thread_counts.get_mut_or_insert(*thread_id_);
                *tc += 1;
                if *tc > thread_count {
                    thread_count = *tc;
                    thread_id = *thread_id_;
                }
            }

            if thread_id == u32::MAX {
                return Ok(None); // This should never happen
            } else if thread_counts.len() == 1 {
                return Ok(Some(thread_id));
            }

            // Delete all but the most common threadId
            let mut batch = BatchBuilder::new();
            let change_id = self.assign_change_id(account_id).await.map_err(|_| {
                tracing::error!(
                    event = "error",
                    context = "find_or_merge_thread",
                    "Failed to assign changeId for thread merge."
                );
                IngestError::Temporary
            })?;
            let mut changes = ChangeLogBuilder::with_change_id(change_id);
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Thread);
            for &delete_thread_id in thread_counts.keys() {
                if delete_thread_id != thread_id {
                    batch.delete_document(delete_thread_id);
                    changes.log_delete(Collection::Thread, delete_thread_id);
                }
            }

            // Move messages to the new threadId
            batch.with_collection(Collection::Email);
            for old_thread_id in thread_ids.into_iter().flatten().collect::<AHashSet<_>>() {
                if thread_id != old_thread_id {
                    for document_id in self
                        .store
                        .get_bitmap(BitmapKey {
                            account_id,
                            collection: Collection::Email.into(),
                            class: BitmapClass::Tag {
                                field: Property::ThreadId.into(),
                                value: TagValue::Id(old_thread_id),
                            },
                            block_num: 0,
                        })
                        .await
                        .map_err(|err| {
                            tracing::error!(
                            event = "error",
                            context = "find_or_merge_thread",
                            error = ?err,
                            "Failed to obtain threadId bitmap.");
                            IngestError::Temporary
                        })?
                        .unwrap_or_default()
                    {
                        batch
                            .update_document(document_id)
                            .assert_value(Property::ThreadId, old_thread_id)
                            .value(Property::ThreadId, old_thread_id, F_BITMAP | F_CLEAR)
                            .value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP);
                        changes.log_move(
                            Collection::Email,
                            Id::from_parts(old_thread_id, document_id),
                            Id::from_parts(thread_id, document_id),
                        );
                    }
                }
            }
            batch.custom(changes);

            match self.store.write(batch.build()).await {
                Ok(_) => return Ok(Some(thread_id)),
                Err(store::Error::AssertValueFailed) if try_count < 3 => {
                    try_count += 1;
                }
                Err(err) => {
                    tracing::error!(
                        event = "error",
                        context = "find_or_merge_thread",
                        error = ?err,
                        "Failed to write thread merge batch.");
                    return Err(IngestError::Temporary);
                }
            }
        }
    }
}

impl From<IngestedEmail> for Object<Value> {
    fn from(email: IngestedEmail) -> Self {
        Object::with_capacity(3)
            .with_property(Property::Id, email.id)
            .with_property(Property::ThreadId, Id::from(email.id.prefix_id()))
            .with_property(Property::BlobId, email.blob_id)
            .with_property(Property::Size, email.size)
    }
}
