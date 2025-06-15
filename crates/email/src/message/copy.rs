/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    index::{MAX_ID_LENGTH, MAX_SORT_FIELD_LENGTH, TrimTextValue, VisitText},
    ingest::{EmailIngest, IngestedEmail, ThreadResult},
    metadata::{MessageData, MessageMetadata},
};
use crate::mailbox::UidMailbox;
use common::{Server, auth::ResourceToken, storage::index::ObjectIndexBuilder};
use jmap_proto::{
    error::set::SetError,
    types::{
        blob::BlobId,
        collection::{Collection, SyncCollection},
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::Property,
    },
};
use mail_parser::{HeaderName, HeaderValue, parsers::fields::thread::thread_name};
use store::{
    BlobClass,
    write::{BatchBuilder, TaskQueueClass, ValueClass, now},
};
use trc::AddContext;

pub trait EmailCopy: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        resource_token: &ResourceToken,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<UTCDate>,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<Result<IngestedEmail, SetError>>> + Send;
}

impl EmailCopy for Server {
    #[allow(clippy::too_many_arguments)]
    async fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        resource_token: &ResourceToken,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<UTCDate>,
        session_id: u64,
    ) -> trc::Result<Result<IngestedEmail, SetError>> {
        // Obtain metadata
        let account_id = resource_token.account_id;
        let mut metadata = if let Some(metadata) = self
            .get_archive_by_property(
                from_account_id,
                Collection::Email,
                from_message_id,
                Property::BodyStructure,
            )
            .await?
        {
            metadata
                .deserialize::<MessageMetadata>()
                .caused_by(trc::location!())?
        } else {
            return Ok(Err(SetError::not_found().with_description(format!(
                "Message not found not found in account {}.",
                Id::from(from_account_id)
            ))));
        };

        // Check quota
        match self
            .has_available_quota(resource_token, metadata.size as u64)
            .await
        {
            Ok(_) => (),
            Err(err) => {
                if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota))
                    || err.matches(trc::EventType::Limit(trc::LimitEvent::TenantQuota))
                {
                    trc::error!(err.account_id(account_id).span_id(session_id));
                    return Ok(Err(SetError::over_quota()));
                } else {
                    return Err(err);
                }
            }
        }

        // Set receivedAt
        if let Some(received_at) = received_at {
            metadata.received_at = received_at.timestamp() as u64;
        }

        // Obtain threadId
        let mut references = Vec::with_capacity(5);
        let mut subject = "";
        let mut message_id = "";
        for header in &metadata.contents[0].parts[0].headers {
            match &header.name {
                HeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() && id.len() < MAX_ID_LENGTH {
                            references.push(id.as_bytes());
                            message_id = id;
                        }
                    });
                }
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        if !id.is_empty() && id.len() < MAX_ID_LENGTH {
                            references.push(id.as_bytes());
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

        // Obtain threadId
        let (is_new_thread, thread_id) = match self
            .find_or_merge_thread(account_id, subject, references, None)
            .await
            .caused_by(trc::location!())?
        {
            ThreadResult::Id(thread_id) => (false, thread_id),
            ThreadResult::Create => (
                true,
                self.store()
                    .assign_document_ids(account_id, Collection::Thread, 1)
                    .await
                    .caused_by(trc::location!())?,
            ),
            ThreadResult::Skip => unreachable!(),
        };

        // Assign id
        let mut email = IngestedEmail {
            size: metadata.size as usize,
            ..Default::default()
        };
        let blob_hash = metadata.blob_hash.clone();

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(mailboxes.len());
        email.imap_uids = Vec::with_capacity(mailboxes.len());
        for mailbox_id in &mailboxes {
            let uid = self
                .assign_imap_uid(account_id, *mailbox_id)
                .await
                .caused_by(trc::location!())?;
            mailbox_ids.push(UidMailbox::new(*mailbox_id, uid));
            email.imap_uids.push(uid);
        }

        // Prepare batch
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        if is_new_thread {
            batch
                .with_collection(Collection::Thread)
                .update_document(thread_id)
                .log_container_insert(SyncCollection::Thread);
        }

        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Email, 1)
            .await
            .caused_by(trc::location!())?;

        batch
            .with_collection(Collection::Email)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new().with_changes(MessageData {
                    mailboxes: mailbox_ids,
                    keywords,
                    thread_id,
                }),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                    due: now(),
                    hash: metadata.blob_hash.clone(),
                }),
                vec![],
            );
        metadata
            .index(
                &mut batch,
                account_id,
                resource_token.tenant.map(|t| t.id),
                true,
            )
            .caused_by(trc::location!())?;

        // Insert and obtain ids
        let change_id = self
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?
            .last_change_id(account_id)?;

        // Request FTS index
        self.notify_task_queue();

        // Update response
        email.id = Id::from_parts(thread_id, document_id);
        email.change_id = change_id;
        email.blob_id = BlobId::new(
            blob_hash,
            BlobClass::Linked {
                account_id,
                collection: Collection::Email.into(),
                document_id,
            },
        );

        Ok(Ok(email))
    }
}
