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

use std::{borrow::Cow, time::Duration};

use common::webhooks::{WebhookIngestSource, WebhookPayload, WebhookType};
use jmap_proto::{
    object::Object,
    types::{
        blob::BlobId, collection::Collection, id::Id, keyword::Keyword, property::Property,
        value::Value,
    },
};
use mail_parser::{
    parsers::fields::thread::thread_name, HeaderName, HeaderValue, Message, MessageParser, PartType,
};

use rand::Rng;
use store::{
    ahash::AHashSet,
    query::Filter,
    write::{
        log::{ChangeLogBuilder, Changes, LogInsert},
        now, AssignedIds, BatchBuilder, BitmapClass, FtsQueueClass, MaybeDynamicId,
        MaybeDynamicValue, SerializeWithId, TagValue, ValueClass, F_BITMAP, F_CLEAR, F_VALUE,
    },
    BitmapKey, BlobClass, Serialize,
};
use utils::map::vec_map::VecMap;

use crate::{
    email::index::{IndexMessage, VisitValues, MAX_ID_LENGTH},
    mailbox::{UidMailbox, INBOX_ID, JUNK_ID},
    services::housekeeper::Event,
    IngestError, JMAP,
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
    pub imap_uids: Vec<u32>,
}

pub struct IngestEmail<'x> {
    pub raw_message: &'x [u8],
    pub message: Option<Message<'x>>,
    pub account_id: u32,
    pub account_quota: i64,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub source: IngestSource,
    pub encrypt: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestSource {
    Smtp,
    Jmap,
    Imap,
}

const MAX_RETRIES: u32 = 10;

impl JMAP {
    #[allow(clippy::blocks_in_conditions)]
    pub async fn email_ingest(
        &self,
        mut params: IngestEmail<'_>,
    ) -> Result<IngestedEmail, IngestError> {
        // Check quota
        let mut raw_message_len = params.raw_message.len() as i64;
        if !self
            .has_available_quota(params.account_id, params.account_quota, raw_message_len)
            .await
            .map_err(|_| IngestError::Temporary)?
        {
            return Err(IngestError::OverQuota);
        }

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.ok_or_else(|| IngestError::Permanent {
            code: [5, 5, 0],
            reason: "Failed to parse e-mail message.".to_string(),
        })?;

        // Check for Spam headers
        if let Some((header_name, header_value)) = &self.core.jmap.spam_header {
            if params.mailbox_ids == [INBOX_ID]
                && message.root_part().headers().iter().any(|header| {
                    &header.name == header_name
                        && header
                            .value()
                            .as_text()
                            .map_or(false, |value| value.contains(header_value))
                })
            {
                params.mailbox_ids[0] = JUNK_ID;
            }
        }

        // Obtain message references and thread name
        let thread_id = {
            let mut references = Vec::with_capacity(5);
            let mut subject = "";
            let mut message_id = "";
            for header in message.root_part().headers().iter().rev() {
                match &header.name {
                    HeaderName::MessageId => header.value.visit_text(|id| {
                        if !id.is_empty() && id.len() < MAX_ID_LENGTH {
                            if message_id.is_empty() {
                                message_id = id;
                            }
                            references.push(id);
                        }
                    }),
                    HeaderName::InReplyTo
                    | HeaderName::References
                    | HeaderName::ResentMessageId => {
                        header.value.visit_text(|id| {
                            if !id.is_empty() && id.len() < MAX_ID_LENGTH {
                                references.push(id);
                            }
                        });
                    }
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
            if params.source == IngestSource::Smtp
                && !message_id.is_empty()
                && !self
                    .core
                    .storage
                    .data
                    .filter(
                        params.account_id,
                        Collection::Email,
                        vec![Filter::eq(Property::MessageId, message_id)],
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
                tracing::debug!(
                    context = "email_ingest",
                    event = "skip",
                    account_id = ?params.account_id,
                    from = ?message.from(),
                    message_id = message_id,
                    "Duplicate message skipped.");

                return Ok(IngestedEmail {
                    id: Id::default(),
                    change_id: u64::MAX,
                    blob_id: BlobId::default(),
                    imap_uids: Vec::new(),
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
                        message = MessageParser::default()
                            .parse(raw_message.as_ref())
                            .ok_or_else(|| IngestError::Permanent {
                                code: [5, 5, 0],
                                reason: "Failed to parse encrypted e-mail message.".to_string(),
                            })?;

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

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(params.mailbox_ids.len());
        let mut imap_uids = Vec::with_capacity(params.mailbox_ids.len());
        for mailbox_id in &params.mailbox_ids {
            let uid = self
                .assign_imap_uid(params.account_id, *mailbox_id)
                .await
                .map_err(|err| {
                    tracing::error!(
                    event = "error",
                    context = "email_ingest",
                    error = ?err,
                    "Failed to assign IMAP UID.");
                    IngestError::Temporary
                })?;
            mailbox_ids.push(UidMailbox::new(*mailbox_id, uid));
            imap_uids.push(uid);
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch
            .with_change_id(change_id)
            .with_account_id(params.account_id)
            .with_collection(Collection::Thread);
        if let Some(thread_id) = thread_id {
            batch.log(Changes::update([thread_id]));
        } else {
            batch.create_document().log(LogInsert());
        }

        // Build write batch
        let maybe_thread_id = thread_id
            .map(MaybeDynamicId::Static)
            .unwrap_or(MaybeDynamicId::Dynamic(0));
        batch
            .with_collection(Collection::Mailbox)
            .log(Changes::child_update(params.mailbox_ids.iter().copied()))
            .with_collection(Collection::Email)
            .create_document()
            .log(LogEmailInsert(thread_id))
            .index_message(
                message,
                blob_id.hash.clone(),
                params.keywords,
                mailbox_ids,
                params.received_at.unwrap_or_else(now),
            )
            .value(Property::Cid, change_id, F_VALUE)
            .set(Property::ThreadId, maybe_thread_id)
            .tag(Property::ThreadId, TagValue::Id(maybe_thread_id), 0)
            .set(
                ValueClass::FtsQueue(FtsQueueClass {
                    seq: self
                        .generate_snowflake_id()
                        .map_err(|_| IngestError::Temporary)?,
                    hash: blob_id.hash.clone(),
                }),
                0u64.serialize(),
            );

        // Insert and obtain ids
        let ids = self
            .core
            .storage
            .data
            .write(batch.build())
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "email_ingest",
                error = ?err,
                "Failed to write message to database.");
                IngestError::Temporary
            })?;
        let thread_id = match thread_id {
            Some(thread_id) => thread_id,
            None => ids
                .first_document_id()
                .map_err(|_| IngestError::Temporary)?,
        };
        let document_id = ids.last_document_id().map_err(|_| IngestError::Temporary)?;
        let id = Id::from_parts(thread_id, document_id);

        // Request FTS index
        let _ = self.inner.housekeeper_tx.send(Event::IndexStart).await;

        tracing::debug!(
            context = "email_ingest",
            event = "success",
            account_id = ?params.account_id,
            document_id = ?document_id,
            mailbox_ids = ?params.mailbox_ids,
            change_id = ?change_id,
            blob_id = ?blob_id.hash,
            size = raw_message_len,
            "Ingested e-mail.");

        // Send webhook event
        if self
            .core
            .has_webhook_subscribers(WebhookType::MessageAppended)
        {
            self.smtp
                .inner
                .ipc
                .send_webhook(
                    WebhookType::MessageAppended,
                    WebhookPayload::MessageAppended {
                        account_id: params.account_id,
                        mailbox_ids: params.mailbox_ids,
                        source: match params.source {
                            IngestSource::Smtp => WebhookIngestSource::Smtp,
                            IngestSource::Jmap => WebhookIngestSource::Jmap,
                            IngestSource::Imap => WebhookIngestSource::Imap,
                        },
                        encrypt: params.encrypt,
                        size: raw_message_len as usize,
                    },
                )
                .await;
        }

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
            imap_uids,
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
                filters.push(Filter::eq(Property::References, *reference));
            }
            filters.push(Filter::End);
            let results = self
                .core
                .storage
                .data
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
                .get_cached_thread_ids(account_id, results.iter())
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
                return Ok(thread_ids
                    .into_iter()
                    .next()
                    .map(|(_, thread_id)| thread_id));
            }

            // Find the most common threadId
            let mut thread_counts = VecMap::<u32, u32>::with_capacity(thread_ids.len());
            let mut thread_id = u32::MAX;
            let mut thread_count = 0;
            for (_, thread_id_) in thread_ids.iter() {
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
            for old_thread_id in thread_ids
                .into_iter()
                .map(|(_, thread_id)| thread_id)
                .collect::<AHashSet<_>>()
            {
                if thread_id != old_thread_id {
                    for document_id in self
                        .core
                        .storage
                        .data
                        .get_bitmap(BitmapKey {
                            account_id,
                            collection: Collection::Email.into(),
                            class: BitmapClass::Tag {
                                field: Property::ThreadId.into(),
                                value: TagValue::Id(old_thread_id),
                            },
                            document_id: 0,
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

            match self.core.storage.data.write(batch.build()).await {
                Ok(_) => return Ok(Some(thread_id)),
                Err(store::Error::AssertValueFailed) if try_count < MAX_RETRIES => {
                    let backoff = rand::thread_rng().gen_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
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

    pub async fn assign_imap_uid(&self, account_id: u32, mailbox_id: u32) -> store::Result<u32> {
        // Increment UID next
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox)
            .update_document(mailbox_id)
            .add_and_get(Property::EmailIds, 1);
        self.core
            .storage
            .data
            .write(batch.build())
            .await
            .and_then(|v| v.last_counter_id().map(|id| id as u32))
    }
}

pub struct LogEmailInsert(Option<u32>);

impl LogEmailInsert {
    pub fn new(thread_id: Option<u32>) -> Self {
        Self(thread_id)
    }
}

impl SerializeWithId for LogEmailInsert {
    fn serialize_with_id(&self, ids: &AssignedIds) -> store::Result<Vec<u8>> {
        let thread_id = match self.0 {
            Some(thread_id) => thread_id,
            None => ids.first_document_id()?,
        };
        let document_id = ids.last_document_id()?;

        Ok(Changes::insert([Id::from_parts(thread_id, document_id)]).serialize())
    }
}

impl From<LogEmailInsert> for MaybeDynamicValue {
    fn from(log: LogEmailInsert) -> Self {
        MaybeDynamicValue::Dynamic(Box::new(log))
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
