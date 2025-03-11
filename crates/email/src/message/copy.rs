/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::ResourceToken};
use jmap_proto::{
    error::set::SetError,
    types::{
        blob::BlobId, collection::Collection, date::UTCDate, id::Id, keyword::Keyword,
        property::Property,
    },
};
use mail_parser::parsers::fields::thread::thread_name;
use store::{
    BlobClass, Serialize, SerializeInfallible,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, MaybeDynamicId, TagValue, TaskQueueClass,
        ValueClass,
        log::{Changes, LogInsert},
    },
};
use trc::AddContext;

use crate::mailbox::UidMailbox;

use super::{
    index::{MAX_ID_LENGTH, MAX_SORT_FIELD_LENGTH, TrimTextValue},
    ingest::{EmailIngest, IngestedEmail, LogEmailInsert},
    metadata::{HeaderName, HeaderValue, MessageMetadata},
};

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
            .get_property::<Archive<AlignedBytes>>(
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
        for header in &metadata.contents[0].parts[0].headers {
            match &header.name {
                HeaderName::MessageId
                | HeaderName::InReplyTo
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

        let thread_id = if !references.is_empty() {
            self.find_or_merge_thread(account_id, subject, &references)
                .await
                .caused_by(trc::location!())?
        } else {
            None
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
        let change_id = self.assign_change_id(account_id)?;
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_change_id(change_id)
            .with_collection(Collection::Thread);
        if let Some(thread_id) = thread_id {
            batch.log(Changes::update([thread_id]));
        } else {
            batch.create_document().log(LogInsert());
        };

        // Build batch
        let maybe_thread_id = thread_id
            .map(MaybeDynamicId::Static)
            .unwrap_or(MaybeDynamicId::Dynamic(0));
        batch
            .with_collection(Collection::Mailbox)
            .log(Changes::child_update(mailboxes.iter().copied()))
            .with_collection(Collection::Email)
            .create_document()
            .log(LogEmailInsert::new(thread_id))
            .set(Property::ThreadId, maybe_thread_id)
            .tag(Property::ThreadId, TagValue::Id(maybe_thread_id))
            .tag_many(Property::MailboxIds, mailbox_ids.iter())
            .set(
                Property::MailboxIds,
                Archiver::new(mailbox_ids)
                    .serialize()
                    .caused_by(trc::location!())?,
            )
            .tag_many(Property::Keywords, keywords.iter())
            .set(
                Property::Keywords,
                Archiver::new(keywords)
                    .serialize()
                    .caused_by(trc::location!())?,
            )
            .set(Property::Cid, change_id.serialize())
            .set(
                ValueClass::TaskQueue(TaskQueueClass::IndexEmail {
                    seq: self.generate_snowflake_id()?,
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
