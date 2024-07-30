/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

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
use trc::AddContext;
use utils::map::vec_map::VecMap;

use crate::{
    email::index::{IndexMessage, VisitValues, MAX_ID_LENGTH},
    mailbox::{UidMailbox, INBOX_ID, JUNK_ID},
    services::housekeeper::Event,
    JMAP,
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
    pub session_id: u64,
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
    pub async fn email_ingest(&self, mut params: IngestEmail<'_>) -> trc::Result<IngestedEmail> {
        // Check quota
        let start_time = Instant::now();
        let mut raw_message_len = params.raw_message.len() as i64;
        self.has_available_quota(params.account_id, params.account_quota, raw_message_len)
            .await
            .caused_by(trc::location!())?;

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.ok_or_else(|| {
            trc::EventType::Store(trc::StoreEvent::IngestError)
                .ctx(trc::Key::Code, 550)
                .ctx(trc::Key::Reason, "Failed to parse e-mail message.")
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
                    .caused_by(trc::location!())?
                    .results
                    .is_empty()
            {
                trc::event!(
                    Store(trc::StoreEvent::IngestDuplicate),
                    SpanId = params.session_id,
                    AccountId = params.account_id,
                    MessageId = message_id.to_string(),
                );

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
                .caused_by(trc::location!())?
            {
                match message.encrypt(&encrypt_params).await {
                    Ok(new_raw_message) => {
                        raw_message = Cow::from(new_raw_message);
                        raw_message_len = raw_message.len() as i64;
                        message = MessageParser::default()
                            .parse(raw_message.as_ref())
                            .ok_or_else(|| {
                                trc::EventType::Store(trc::StoreEvent::IngestError)
                                    .ctx(trc::Key::Code, 550)
                                    .ctx(
                                        trc::Key::Reason,
                                        "Failed to parse encrypted e-mail message.",
                                    )
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
                        trc::bail!(trc::StoreEvent::CryptoError
                            .into_err()
                            .caused_by(trc::location!())
                            .reason(err));
                    }
                    _ => unreachable!(),
                }
            }
        }

        // Obtain a documentId and changeId
        let change_id = self
            .assign_change_id(params.account_id)
            .await
            .caused_by(trc::location!())?;

        // Store blob
        let blob_id = self
            .put_blob(params.account_id, raw_message.as_ref(), false)
            .await
            .caused_by(trc::location!())?;

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(params.mailbox_ids.len());
        let mut imap_uids = Vec::with_capacity(params.mailbox_ids.len());
        for mailbox_id in &params.mailbox_ids {
            let uid = self
                .assign_imap_uid(params.account_id, *mailbox_id)
                .await
                .caused_by(trc::location!())?;
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
        let mailbox_ids_event = mailbox_ids
            .iter()
            .map(|m| trc::Value::from(m.mailbox_id))
            .collect::<Vec<_>>();
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
                    seq: self.generate_snowflake_id().caused_by(trc::location!())?,
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
            .caused_by(trc::location!())?;
        let thread_id = match thread_id {
            Some(thread_id) => thread_id,
            None => ids.first_document_id().caused_by(trc::location!())?,
        };
        let document_id = ids.last_document_id().caused_by(trc::location!())?;
        let id = Id::from_parts(thread_id, document_id);

        // Request FTS index
        let _ = self.inner.housekeeper_tx.send(Event::IndexStart).await;

        trc::event!(
            Store(trc::StoreEvent::Ingest),
            SpanId = params.session_id,
            AccountId = params.account_id,
            DocumentId = document_id,
            MailboxId = mailbox_ids_event,
            BlobId = blob_id.hash.to_hex(),
            ChangeId = change_id,
            Size = raw_message_len as u64,
            Elapsed = start_time.elapsed(),
        );

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
    ) -> trc::Result<Option<u32>> {
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
                .caused_by(trc::location!())?
                .results;

            if results.is_empty() {
                return Ok(None);
            }

            // Obtain threadIds for matching messages
            let thread_ids = self
                .get_cached_thread_ids(account_id, results.iter())
                .await
                .caused_by(trc::location!())?;

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
            let change_id = self
                .assign_change_id(account_id)
                .await
                .caused_by(trc::location!())?;
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
                        .caused_by(trc::location!())?
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
                Err(err) if err.is_assertion_failure() && try_count < MAX_RETRIES => {
                    let backoff = rand::thread_rng().gen_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    try_count += 1;
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    pub async fn assign_imap_uid(&self, account_id: u32, mailbox_id: u32) -> trc::Result<u32> {
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
    fn serialize_with_id(&self, ids: &AssignedIds) -> trc::Result<Vec<u8>> {
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
