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
    query::Filter,
    write::{log::ChangeLogBuilder, now, BatchBuilder, F_BITMAP, F_CLEAR, F_VALUE},
    BlobHash, ValueKey,
};
use utils::map::vec_map::VecMap;

use crate::{
    email::index::{IndexMessage, MAX_ID_LENGTH},
    MaybeError, JMAP,
};

use super::index::{TrimTextValue, MAX_SORT_FIELD_LENGTH};

pub struct IngestedEmail {
    pub id: Id,
    pub change_id: u64,
    pub blob_hash: BlobHash,
    pub size: usize,
}

impl JMAP {
    pub async fn email_ingest(
        &self,
        raw_message: &[u8],
        account_id: u32,
        mailbox_ids: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<u64>,
    ) -> Result<IngestedEmail, MaybeError> {
        // Parse message
        let message = Message::parse(raw_message)
            .ok_or_else(|| MaybeError::Permanent("Failed to parse e-mail message.".to_string()))?;

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
        let thread_id = if !references.is_empty() {
            self.find_or_merge_thread(account_id, subject, &references)
                .await?
        } else {
            None
        };

        // Store blob
        let blob_hash = self.store.write_blob(account_id, raw_message).await?;

        // Obtain a documentId and changeId
        let document_id = self
            .store
            .assign_document_id(account_id, Collection::Email)
            .await?;
        let change_id = self
            .store
            .assign_change_id(account_id, Collection::Email)
            .await?;

        // Build change log
        let mut changes = ChangeLogBuilder::with_change_id(change_id);
        let thread_id = if let Some(thread_id) = thread_id {
            changes.log_child_update(Collection::Thread, thread_id);
            thread_id
        } else {
            let thread_id = self
                .store
                .assign_document_id(account_id, Collection::Thread)
                .await?;
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
        batch.index_message(
            message,
            blob_hash,
            keywords,
            mailbox_ids,
            received_at.unwrap_or_else(now),
            self.config.default_language,
        )?;
        batch.value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP);
        batch.custom(changes)?;
        self.store.write(batch.build()).await?;

        Ok(IngestedEmail {
            id,
            change_id,
            blob_hash,
            size: raw_message.len(),
        })
    }

    async fn find_or_merge_thread(
        &self,
        account_id: u32,
        thread_name: &str,
        references: &[&str],
    ) -> Result<Option<u32>, MaybeError> {
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
                .await?
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
                .await?;
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
                .assign_change_id(account_id, Collection::Thread)
                .await?;
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
            for (document_id, old_thread_id) in results.iter().zip(thread_ids.into_iter()) {
                let old_thread_id = old_thread_id.unwrap_or(u32::MAX);
                if thread_id != old_thread_id {
                    batch
                        .update_document(document_id)
                        .assert_value(Property::ThreadId, old_thread_id)
                        .value(Property::ThreadId, old_thread_id, F_BITMAP | F_CLEAR)
                        .value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP);
                    changes.log_move(
                        Collection::Email,
                        Id::from_parts(old_thread_id, document_id),
                        Id::from_parts(thread_id, document_id),
                    )
                }
            }
            batch.custom(changes)?;

            match self.store.write(batch.build()).await {
                Ok(_) => return Ok(Some(thread_id)),
                Err(store::Error::AssertValueFailed) if try_count < 3 => {
                    try_count += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

impl From<IngestedEmail> for Object<Value> {
    fn from(email: IngestedEmail) -> Self {
        Object::with_capacity(3)
            .with_property(Property::Id, email.id)
            .with_property(Property::ThreadId, email.id.prefix_id())
            .with_property(Property::BlobId, BlobId::new(email.blob_hash))
    }
}
