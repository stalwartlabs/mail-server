/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    collections::BTreeSet,
    fmt::Write,
    time::{Duration, Instant},
};

use common::{
    Server,
    auth::{AccessToken, ResourceToken},
    storage::index::ObjectIndexBuilder,
};
use directory::Permission;
use jmap_proto::types::{
    blob::BlobId,
    collection::Collection,
    id::Id,
    keyword::Keyword,
    property::Property,
    value::{Object, Value},
};
use mail_parser::{
    Header, HeaderName, HeaderValue, Message, MessageParser, PartType,
    parsers::fields::thread::thread_name,
};

use spam_filter::{
    SpamFilterInput, analysis::init::SpamFilterInit, modules::bayes::BayesClassifier,
};
use std::future::Future;
use store::{
    BlobClass, IndexKey, IndexKeyPrefix, IterateParams, U32_LEN,
    ahash::AHashMap,
    query::Filter,
    roaring::RoaringBitmap,
    write::{
        AlignedBytes, Archive, AssignedIds, BatchBuilder, MaybeDynamicValue, SerializeWithId,
        TaskQueueClass, ValueClass,
        key::DeserializeBigEndian,
        log::{ChangeLogBuilder, Changes, LogInsert},
        now,
    },
};
use store::{SerializeInfallible, rand::Rng};
use trc::{AddContext, MessageIngestEvent};

use crate::{
    mailbox::{INBOX_ID, JUNK_ID, UidMailbox},
    message::{
        crypto::EncryptionParams,
        index::{IndexMessage, MAX_ID_LENGTH, VisitValues},
        metadata::MessageData,
    },
    thread::cache::ThreadCache,
};

use super::{
    crypto::{EncryptMessage, EncryptMessageError},
    index::{MAX_SORT_FIELD_LENGTH, TrimTextValue},
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
    pub resource: ResourceToken,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub source: IngestSource<'x>,
    pub spam_classify: bool,
    pub spam_train: bool,
    pub session_id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestSource<'x> {
    Smtp { deliver_to: &'x str },
    Jmap,
    Imap,
    Restore,
}

const MAX_RETRIES: u32 = 10;

pub trait EmailIngest: Sync + Send {
    fn email_ingest(
        &self,
        params: IngestEmail,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;
    fn find_or_merge_thread(
        &self,
        account_id: u32,
        thread_name: &str,
        references: &[&str],
    ) -> impl Future<Output = trc::Result<u32>> + Send;
    fn assign_imap_uid(
        &self,
        account_id: u32,
        mailbox_id: u32,
    ) -> impl Future<Output = trc::Result<u32>> + Send;
    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool;
    fn create_thread_id(&self, account_id: u32) -> impl Future<Output = trc::Result<u32>> + Send;
}

impl EmailIngest for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn email_ingest(&self, mut params: IngestEmail<'_>) -> trc::Result<IngestedEmail> {
        // Check quota
        let start_time = Instant::now();
        let account_id = params.resource.account_id;
        let tenant_id = params.resource.tenant.map(|t| t.id);
        let mut raw_message_len = params.raw_message.len() as u64;
        self.has_available_quota(&params.resource, raw_message_len)
            .await
            .caused_by(trc::location!())?;

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.ok_or_else(|| {
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(trc::Key::Code, 550)
                .ctx(trc::Key::Reason, "Failed to parse e-mail message.")
        })?;

        let mut is_spam = false;
        let mut train_spam = None;
        let mut extra_headers = String::new();
        let mut extra_headers_parsed = Vec::new();
        match params.source {
            IngestSource::Smtp { deliver_to } => {
                // Add delivered to header
                if self.core.smtp.session.data.add_delivered_to {
                    extra_headers = format!("Delivered-To: {deliver_to}\r\n");
                    extra_headers_parsed.push(Header {
                        name: HeaderName::Other("Delivered-To".into()),
                        value: HeaderValue::Text(deliver_to.into()),
                        offset_field: 0,
                        offset_start: 13,
                        offset_end: extra_headers.len(),
                    });
                }

                // Spam classification and training
                if params.spam_classify
                    && self.core.spam.enabled
                    && params.mailbox_ids == [INBOX_ID]
                {
                    // Set the spam filter result
                    is_spam = self
                        .core
                        .spam
                        .headers
                        .status
                        .as_ref()
                        .and_then(|name| message.header(name.as_str()).and_then(|v| v.as_text()))
                        .is_some_and(|v| v.contains("Yes"));

                    // Classify the message with user's model
                    if let Some(bayes_config) = self
                        .core
                        .spam
                        .bayes
                        .as_ref()
                        .filter(|config| config.account_classify && params.spam_train)
                    {
                        // Initialize spam filter
                        let ctx = self.spam_filter_init(SpamFilterInput::from_account_message(
                            &message,
                            account_id,
                            params.session_id,
                        ));

                        // Bayes classify
                        match self.bayes_classify(&ctx).await {
                            Ok(Some(score)) => {
                                let result = if score > bayes_config.score_spam {
                                    is_spam = true;
                                    "Yes"
                                } else if score < bayes_config.score_ham {
                                    is_spam = false;
                                    "No"
                                } else {
                                    "Unknown"
                                };

                                if let Some(header) = &self.core.spam.headers.bayes_result {
                                    let offset_field = extra_headers.len();
                                    let offset_start = offset_field + header.len() + 1;

                                    let _ = write!(
                                        &mut extra_headers,
                                        "{header}: {result}, {score:.2}\r\n",
                                    );

                                    extra_headers_parsed.push(Header {
                                        name: HeaderName::Other(header.into()),
                                        value: HeaderValue::Text(
                                            extra_headers
                                                [offset_start + 1..extra_headers.len() - 2]
                                                .into(),
                                        ),
                                        offset_field,
                                        offset_start,
                                        offset_end: extra_headers.len(),
                                    });
                                }
                            }
                            Ok(None) => (),
                            Err(err) => {
                                trc::error!(err.caused_by(trc::location!()));
                            }
                        }
                    }

                    if is_spam {
                        params.mailbox_ids[0] = JUNK_ID;
                        params.keywords.push(Keyword::Junk);
                    }
                }
            }
            IngestSource::Jmap | IngestSource::Imap
                if params.spam_train && self.core.spam.enabled =>
            {
                if params.keywords.contains(&Keyword::Junk) {
                    train_spam = Some(true);
                } else if params.keywords.contains(&Keyword::NotJunk) {
                    train_spam = Some(false);
                } else if params.mailbox_ids[0] == JUNK_ID {
                    train_spam = Some(true);
                } else if params.mailbox_ids[0] == INBOX_ID {
                    train_spam = Some(false);
                }
            }

            _ => (),
        }

        // Obtain message references and thread name
        let mut message_id = String::new();
        let thread_id = {
            let mut references = Vec::with_capacity(5);
            let mut subject = "";
            for header in message.root_part().headers().iter().rev() {
                match &header.name {
                    HeaderName::MessageId => header.value.visit_text(|id| {
                        if !id.is_empty() && id.len() < MAX_ID_LENGTH {
                            if message_id.is_empty() {
                                message_id = id.to_string();
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
            if params.source.is_smtp()
                && !message_id.is_empty()
                && !self
                    .core
                    .storage
                    .data
                    .filter(
                        account_id,
                        Collection::Email,
                        vec![
                            Filter::eq(Property::MessageId, message_id.as_str().serialize()),
                            Filter::is_in_bitmap(
                                Property::MailboxIds,
                                params.mailbox_ids.first().copied().unwrap_or(INBOX_ID),
                            ),
                        ],
                    )
                    .await
                    .caused_by(trc::location!())?
                    .results
                    .is_empty()
            {
                trc::event!(
                    MessageIngest(MessageIngestEvent::Duplicate),
                    SpanId = params.session_id,
                    AccountId = account_id,
                    MessageId = message_id,
                );

                return Ok(IngestedEmail {
                    id: Id::default(),
                    change_id: u64::MAX,
                    blob_id: BlobId::default(),
                    imap_uids: Vec::new(),
                    size: 0,
                });
            }

            self.find_or_merge_thread(account_id, subject, &references)
                .await?
        };

        // Add additional headers to message
        if !extra_headers.is_empty() {
            let offset_start = extra_headers.len();
            raw_message_len += offset_start as u64;
            let mut new_message = Vec::with_capacity(raw_message_len as usize);
            new_message.extend_from_slice(extra_headers.as_bytes());
            new_message.extend_from_slice(raw_message.as_ref());
            raw_message = Cow::from(new_message);
            message.raw_message = raw_message.as_ref().into();

            // Adjust offsets
            let mut part_iter_stack = Vec::new();
            let mut part_iter = message.parts.iter_mut();

            loop {
                if let Some(part) = part_iter.next() {
                    // Increment header offsets
                    for header in part.headers.iter_mut() {
                        header.offset_field += offset_start;
                        header.offset_start += offset_start;
                        header.offset_end += offset_start;
                    }

                    // Adjust part offsets
                    part.offset_body += offset_start;
                    part.offset_end += offset_start;
                    part.offset_header += offset_start;

                    if let PartType::Message(sub_message) = &mut part.body {
                        if sub_message.root_part().offset_header != 0 {
                            sub_message.raw_message = raw_message.as_ref().into();
                            part_iter_stack.push(part_iter);
                            part_iter = sub_message.parts.iter_mut();
                        }
                    }
                } else if let Some(iter) = part_iter_stack.pop() {
                    part_iter = iter;
                } else {
                    break;
                }
            }

            // Add extra headers to root part
            let root_part = &mut message.parts[0];
            root_part.offset_header = 0;
            extra_headers_parsed.append(&mut root_part.headers);
            root_part.headers = extra_headers_parsed;
        }

        // Encrypt message
        let do_encrypt = match params.source {
            IngestSource::Jmap | IngestSource::Imap => {
                self.core.jmap.encrypt && self.core.jmap.encrypt_append
            }
            IngestSource::Smtp { .. } => self.core.jmap.encrypt,
            IngestSource::Restore => false,
        };
        if do_encrypt && !message.is_encrypted() {
            if let Some(encrypt_params_) = self
                .get_property::<Archive<AlignedBytes>>(
                    account_id,
                    Collection::Principal,
                    0,
                    Property::Parameters,
                )
                .await
                .caused_by(trc::location!())?
            {
                let encrypt_params = encrypt_params_
                    .unarchive::<EncryptionParams>()
                    .caused_by(trc::location!())?;
                match message.encrypt(encrypt_params).await {
                    Ok(new_raw_message) => {
                        raw_message = Cow::from(new_raw_message);
                        raw_message_len = raw_message.len() as u64;
                        message = MessageParser::default()
                            .parse(raw_message.as_ref())
                            .ok_or_else(|| {
                                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
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
                        trc::bail!(
                            trc::StoreEvent::CryptoError
                                .into_err()
                                .caused_by(trc::location!())
                                .reason(err)
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }

        // Obtain a documentId and changeId
        let change_id = self
            .assign_change_id(account_id)
            .caused_by(trc::location!())?;

        // Store blob
        let blob_id = self
            .put_blob(account_id, raw_message.as_ref(), false)
            .await
            .caused_by(trc::location!())?;

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(params.mailbox_ids.len());
        let mut imap_uids = Vec::with_capacity(params.mailbox_ids.len());
        for mailbox_id in &params.mailbox_ids {
            let uid = self
                .assign_imap_uid(account_id, *mailbox_id)
                .await
                .caused_by(trc::location!())?;
            mailbox_ids.push(UidMailbox::new(*mailbox_id, uid));
            imap_uids.push(uid);
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch
            .with_change_id(change_id)
            .with_account_id(account_id)
            .with_collection(Collection::Thread)
            .log(Changes::update([thread_id]));
        // Build write batch
        let mailbox_ids_event = mailbox_ids
            .iter()
            .map(|m| trc::Value::from(m.mailbox_id))
            .collect::<Vec<_>>();
        batch
            .with_collection(Collection::Mailbox)
            .log(Changes::child_update(params.mailbox_ids.iter().copied()))
            .with_collection(Collection::Email)
            .create_document()
            .log(LogEmailInsert(thread_id.into()))
            .index_message(
                account_id,
                tenant_id,
                message,
                blob_id.hash.clone(),
                MessageData {
                    mailboxes: mailbox_ids,
                    keywords: params.keywords,
                    change_id,
                    thread_id,
                },
                params.received_at.unwrap_or_else(now),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                    seq: self.generate_snowflake_id().caused_by(trc::location!())?,
                    hash: blob_id.hash.clone(),
                }),
                vec![],
            );

        // Request spam training
        if let Some(learn_spam) = train_spam {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::BayesTrain {
                    seq: self.generate_snowflake_id()?,
                    hash: blob_id.hash.clone(),
                    learn_spam,
                }),
                vec![],
            );
        }

        // Insert and obtain ids
        let ids = self
            .core
            .storage
            .data
            .write(batch.build())
            .await
            .caused_by(trc::location!())?;

        let document_id = ids.last_document_id().caused_by(trc::location!())?;
        let id = Id::from_parts(thread_id, document_id);

        // Request FTS index
        self.notify_task_queue();

        trc::event!(
            MessageIngest(match params.source {
                IngestSource::Smtp { .. } =>
                    if !is_spam {
                        MessageIngestEvent::Ham
                    } else {
                        MessageIngestEvent::Spam
                    },
                IngestSource::Jmap | IngestSource::Restore => MessageIngestEvent::JmapAppend,
                IngestSource::Imap => MessageIngestEvent::ImapAppend,
            }),
            SpanId = params.session_id,
            AccountId = account_id,
            DocumentId = document_id,
            MailboxId = mailbox_ids_event,
            BlobId = blob_id.hash.to_hex(),
            ChangeId = change_id,
            MessageId = message_id,
            Size = raw_message_len,
            Elapsed = start_time.elapsed(),
        );

        Ok(IngestedEmail {
            id,
            change_id,
            blob_id: BlobId {
                hash: blob_id.hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                },
                section: blob_id.section,
            },
            size: raw_message_len as usize,
            imap_uids,
        })
    }

    async fn find_or_merge_thread(
        &self,
        account_id: u32,
        thread_name: &str,
        references: &[&str],
    ) -> trc::Result<u32> {
        if references.is_empty() {
            return self.create_thread_id(account_id).await;
        }

        let mut try_count = 0;
        let thread_name = if !thread_name.is_empty() {
            thread_name
        } else {
            "!"
        }
        .serialize();
        let references = references
            .iter()
            .map(|r| r.as_bytes())
            .collect::<BTreeSet<_>>();

        loop {
            // Find messages with a matching subject
            let mut subj_results = RoaringBitmap::new();
            self.store()
                .iterate(
                    IterateParams::new(
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: 0,
                            field: Property::Subject.into(),
                            key: thread_name.clone(),
                        },
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: u32::MAX,
                            field: Property::Subject.into(),
                            key: thread_name.clone(),
                        },
                    )
                    .no_values()
                    .ascending(),
                    |key, _| {
                        let id_pos = key.len() - U32_LEN;
                        let value = key.get(IndexKeyPrefix::len()..id_pos).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;

                        if value == thread_name {
                            subj_results.insert(key.deserialize_be_u32(id_pos)?);
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            if subj_results.is_empty() {
                return self.create_thread_id(account_id).await;
            }

            // Find messages with matching references
            let mut results = RoaringBitmap::new();
            self.store()
                .iterate(
                    IterateParams::new(
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: 0,
                            field: Property::References.into(),
                            key: references.first().unwrap().to_vec(),
                        },
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: u32::MAX,
                            field: Property::References.into(),
                            key: references.last().unwrap().to_vec(),
                        },
                    )
                    .no_values()
                    .ascending(),
                    |key, _| {
                        let id_pos = key.len() - U32_LEN;
                        let value = key.get(IndexKeyPrefix::len()..id_pos).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;
                        let document_id = key.deserialize_be_u32(id_pos)?;

                        if subj_results.contains(document_id) && references.contains(value) {
                            results.insert(document_id);
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            if results.is_empty() {
                return self.create_thread_id(account_id).await;
            }

            // Find the most common threadId
            let mut thread_counts = AHashMap::<u32, u32>::with_capacity(16);
            let mut thread_id = u32::MAX;
            let mut thread_count = 0;
            let thread_cache = self
                .get_cached_thread_ids(account_id)
                .await
                .caused_by(trc::location!())?;
            for (document_id, thread_id_) in thread_cache.threads.iter() {
                if results.contains(*document_id) {
                    let tc = thread_counts.entry(*thread_id_).or_default();
                    *tc += 1;
                    if *tc > thread_count {
                        thread_count = *tc;
                        thread_id = *thread_id_;
                    }
                }
            }

            if thread_id == u32::MAX {
                return self.create_thread_id(account_id).await;
            } else if thread_counts.len() == 1 {
                return Ok(thread_id);
            }

            // Delete all but the most common threadId
            let mut batch = BatchBuilder::new();
            let change_id = self
                .assign_change_id(account_id)
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

            for (&document_id, &old_thread_id) in &thread_cache.threads {
                if thread_id == old_thread_id || !thread_counts.contains_key(&old_thread_id) {
                    continue;
                }
                if let Some(data_) = self
                    .get_property::<Archive<AlignedBytes>>(
                        account_id,
                        Collection::Email,
                        document_id,
                        Property::Value,
                    )
                    .await
                    .caused_by(trc::location!())?
                {
                    let data = data_
                        .to_unarchived::<MessageData>()
                        .caused_by(trc::location!())?;
                    if data.inner.thread_id != old_thread_id {
                        continue;
                    }
                    let mut new_data = data.deserialize().caused_by(trc::location!())?;
                    new_data.thread_id = thread_id;
                    batch
                        .update_document(document_id)
                        .custom(
                            ObjectIndexBuilder::new()
                                .with_current(data)
                                .with_changes(new_data),
                        )
                        .caused_by(trc::location!())?;
                    changes.log_move(
                        Collection::Email,
                        Id::from_parts(old_thread_id, document_id),
                        Id::from_parts(thread_id, document_id),
                    );
                }
            }

            batch.custom(changes).caused_by(trc::location!())?;

            match self.core.storage.data.write(batch.build()).await {
                Ok(_) => return Ok(thread_id),
                Err(err) if err.is_assertion_failure() && try_count < MAX_RETRIES => {
                    let backoff = store::rand::rng().random_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    try_count += 1;
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    async fn assign_imap_uid(&self, account_id: u32, mailbox_id: u32) -> trc::Result<u32> {
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

    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool {
        self.core.spam.bayes.as_ref().is_some_and(|bayes| {
            bayes.account_classify && access_token.has_permission(Permission::SpamFilterTrain)
        })
    }

    async fn create_thread_id(&self, account_id: u32) -> trc::Result<u32> {
        let mut batch = BatchBuilder::new();
        batch
            .with_change_id(self.generate_snowflake_id().caused_by(trc::location!())?)
            .with_account_id(account_id)
            .with_collection(Collection::Thread)
            .create_document()
            .log(LogInsert());
        self.store()
            .write_expect_id(batch)
            .await
            .caused_by(trc::location!())
    }
}

pub struct LogEmailInsert(Option<u32>);

impl LogEmailInsert {
    pub fn new(thread_id: Option<u32>) -> Self {
        Self(thread_id)
    }
}

impl IngestSource<'_> {
    pub fn is_smtp(&self) -> bool {
        matches!(self, Self::Smtp { .. })
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

/*

 let thread_id = match thread_id {
            Some(thread_id) => thread_id,
            None => ids.first_document_id().caused_by(trc::location!())?,
        };

 .with_collection(Collection::Thread);
        if let Some(thread_id) = thread_id {
            batch.log(Changes::update([thread_id]));
        } else {
            batch.create_document().log(LogInsert());


*/
