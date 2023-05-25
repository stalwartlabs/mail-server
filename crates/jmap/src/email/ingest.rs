use jmap_proto::{
    object::Object,
    types::{
        blob::BlobId, collection::Collection, id::Id, keyword::Keyword, property::Property,
        value::Value,
    },
};
use mail_parser::{
    parsers::fields::thread::thread_name, HeaderName, HeaderValue, Message, RfcHeader,
};
use store::{
    ahash::AHashSet,
    query::Filter,
    write::{log::ChangeLogBuilder, now, BatchBuilder, F_BITMAP, F_CLEAR, F_VALUE},
    BitmapKey, ValueKey,
};
use utils::map::vec_map::VecMap;

use crate::{
    email::index::{IndexMessage, MAX_ID_LENGTH},
    IngestError, JMAP,
};

use super::index::{TrimTextValue, MAX_SORT_FIELD_LENGTH};

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
}

impl JMAP {
    #[allow(clippy::blocks_in_if_conditions)]
    pub async fn email_ingest(
        &self,
        ingest_email: IngestEmail<'_>,
        account_id: u32,
        mailbox_ids: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<u64>,
        skip_duplicates: bool,
    ) -> Result<IngestedEmail, IngestError> {
        // Parse message
        let raw_message = ingest_email.raw_message;
        let message = ingest_email.message.ok_or_else(|| IngestError::Permanent {
            code: [5, 5, 0],
            reason: "Failed to parse e-mail message.".to_string(),
        })?;

        // Obtain message references and thread name
        let mut references = Vec::with_capacity(5);
        let mut subject = "";
        for header in message.root_part().headers().iter().rev() {
            match header.name {
                HeaderName::Rfc(
                    RfcHeader::MessageId
                    | RfcHeader::InReplyTo
                    | RfcHeader::References
                    | RfcHeader::ResentMessageId,
                ) => match &header.value {
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
                HeaderName::Rfc(RfcHeader::Subject) if subject.is_empty() => {
                    subject = thread_name(match &header.value {
                        HeaderValue::Text(text) => text.as_ref(),
                        HeaderValue::TextList(list) if !list.is_empty() => {
                            list.first().unwrap().as_ref()
                        }
                        _ => "",
                    })
                    .trim_text(MAX_SORT_FIELD_LENGTH);
                    if subject.is_empty() {
                        subject = "!";
                    }
                }
                _ => (),
            }
        }

        // Check for duplicates
        if skip_duplicates
            && !references.is_empty()
            && !self
                .store
                .filter(
                    account_id,
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

        let thread_id = if !references.is_empty() {
            self.find_or_merge_thread(account_id, subject, &references)
                .await?
        } else {
            None
        };

        // Obtain a documentId and changeId
        let document_id = self
            .store
            .assign_document_id(account_id, Collection::Email)
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
            .store
            .assign_change_id(account_id)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "email_ingest",
                    error = ?err,
                    "Failed to assign changeId.");
                IngestError::Temporary
            })?;

        // Store blob
        let blob_id = BlobId::maildir(account_id, document_id);
        self.store
            .put_blob(&blob_id.kind, raw_message)
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "email_ingest",
                error = ?err,
                "Failed to write blob.");
                IngestError::Temporary
            })?;

        // Build change log
        let mut changes = ChangeLogBuilder::with_change_id(change_id);
        let thread_id = if let Some(thread_id) = thread_id {
            changes.log_child_update(Collection::Thread, thread_id);
            thread_id
        } else {
            let thread_id = self
                .store
                .assign_document_id(account_id, Collection::Thread)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "email_ingest",
                        error = ?err,
                        "Failed to assign documentId for new thread.");
                    IngestError::Temporary
                })?;
            changes.log_insert(Collection::Thread, thread_id);
            thread_id
        };
        let id = Id::from_parts(thread_id, document_id);
        changes.log_insert(Collection::Email, id);
        for mailbox_id in &mailbox_ids {
            changes.log_child_update(Collection::Mailbox, *mailbox_id);
        }

        // Build write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .create_document(document_id)
            .index_message(
                message,
                keywords,
                mailbox_ids,
                received_at.unwrap_or_else(now),
                self.config.default_language,
            )
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "email_ingest",
                    error = ?err,
                    "Failed to index message.");
                IngestError::Temporary
            })?
            .value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP)
            .custom(changes);
        self.store.write(batch.build()).await.map_err(|err| {
            tracing::error!(
                event = "error",
                context = "email_ingest",
                error = ?err,
                "Failed to write message to database.");
            IngestError::Temporary
        })?;

        Ok(IngestedEmail {
            id,
            change_id,
            blob_id,
            size: raw_message.len(),
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
            filters.push(Filter::eq(Property::Subject, thread_name));
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
                        .map(|document_id| {
                            ValueKey::new(
                                account_id,
                                Collection::Email,
                                document_id,
                                Property::ThreadId,
                            )
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
            let change_id = self
                .store
                .assign_change_id(account_id)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "find_or_merge_thread",
                        error = ?err,
                        "Failed to assign changeId for thread merge.");
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
                        .get_bitmap(BitmapKey::value(
                            account_id,
                            Collection::Email,
                            Property::ThreadId,
                            old_thread_id,
                        ))
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

impl<'x> From<&'x [u8]> for IngestEmail<'x> {
    fn from(raw_message: &'x [u8]) -> Self {
        IngestEmail {
            raw_message,
            message: Message::parse(raw_message),
        }
    }
}

impl<'x> From<&'x Vec<u8>> for IngestEmail<'x> {
    fn from(raw_message: &'x Vec<u8>) -> Self {
        IngestEmail {
            raw_message,
            message: Message::parse(raw_message),
        }
    }
}

impl<'x> IngestEmail<'x> {
    pub fn new(raw_message: &'x [u8], message: Message<'x>) -> Self {
        IngestEmail {
            raw_message,
            message: message.into(),
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
