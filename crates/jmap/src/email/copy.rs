/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse, RequestArguments},
        set::{self, SetRequest},
    },
    request::{
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeReference,
        Call, RequestMethod,
    },
    response::references::EvalObjectReferences,
    types::{
        acl::Acl,
        blob::BlobId,
        collection::Collection,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::Property,
        state::{State, StateChange},
        type_state::DataType,
        value::{MaybePatchValue, Value},
    },
};
use mail_parser::{parsers::fields::thread::thread_name, HeaderName, HeaderValue};
use store::{
    write::{
        log::{Changes, LogInsert},
        BatchBuilder, Bincode, FtsQueueClass, MaybeDynamicId, TagValue, ValueClass, F_BITMAP,
        F_VALUE,
    },
    BlobClass, Serialize,
};
use trc::AddContext;
use utils::map::vec_map::VecMap;

use crate::{auth::AccessToken, mailbox::UidMailbox, services::housekeeper::Event, JMAP};

use super::{
    index::{EmailIndexBuilder, TrimTextValue, VisitValues, MAX_ID_LENGTH, MAX_SORT_FIELD_LENGTH},
    ingest::{IngestedEmail, LogEmailInsert},
    metadata::MessageMetadata,
};

impl JMAP {
    pub async fn email_copy(
        &self,
        request: CopyRequest<RequestArguments>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod>>,
    ) -> trc::Result<CopyResponse> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapCause::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let old_state = self
            .assert_state(account_id, Collection::Email, &request.if_in_state)
            .await?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
            state_change: None,
        };

        let from_message_ids = self
            .owned_or_shared_messages(access_token, from_account_id, Acl::ReadItems)
            .await?;
        let mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            self.shared_documents(access_token, account_id, Collection::Mailbox, Acl::AddItems)
                .await?
                .into()
        } else {
            None
        };
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();

        // Obtain quota
        let account_quota = self.get_quota(access_token, account_id).await?;

        'create: for (id, create) in request.create {
            let id = id.unwrap();
            let from_message_id = id.document_id();
            if !from_message_ids.contains(from_message_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }

            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            for (property, value) in create.properties {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };

                match (property, value) {
                    (Property::MailboxIds, MaybePatchValue::Value(Value::List(ids))) => {
                        mailboxes = ids
                            .into_iter()
                            .filter_map(|id| id.try_unwrap_id()?.document_id().into())
                            .collect();
                    }

                    (Property::MailboxIds, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(id) = patch.next().unwrap().try_unwrap_id() {
                            let document_id = id.document_id();
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !mailboxes.contains(&document_id) {
                                    mailboxes.push(document_id);
                                }
                            } else {
                                mailboxes.retain(|id| id != &document_id);
                            }
                        }
                    }

                    (Property::Keywords, MaybePatchValue::Value(Value::List(keywords_))) => {
                        keywords = keywords_
                            .into_iter()
                            .filter_map(|keyword| keyword.try_unwrap_keyword())
                            .collect();
                    }

                    (Property::Keywords, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(keyword) = patch.next().unwrap().try_unwrap_keyword() {
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !keywords.contains(&keyword) {
                                    keywords.push(keyword);
                                }
                            } else {
                                keywords.retain(|k| k != &keyword);
                            }
                        }
                    }
                    (Property::ReceivedAt, MaybePatchValue::Value(Value::Date(value))) => {
                        received_at = value.into();
                    }
                    (property, _) => {
                        response.not_created.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(property)
                                .with_description("Invalid property or value.".to_string()),
                        );
                        continue 'create;
                    }
                }
            }

            // Make sure message belongs to at least one mailbox
            if mailboxes.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message has to belong to at least one mailbox."),
                );
                continue 'create;
            }

            // Verify that the mailboxIds are valid
            for mailbox_id in &mailboxes {
                if !mailbox_ids.contains(*mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description(format!("mailboxId {mailbox_id} does not exist.")),
                    );
                    continue 'create;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'create;
                }
            }

            // Add response
            match self
                .copy_message(
                    from_account_id,
                    from_message_id,
                    account_id,
                    account_quota,
                    mailboxes,
                    keywords,
                    received_at,
                )
                .await?
            {
                Ok(email) => {
                    response.created.append(id, email.into());
                }
                Err(err) => {
                    response.not_created.append(id, err);
                }
            }

            // Add to destroy list
            if on_success_delete {
                destroy_ids.push(id);
            }
        }

        // Update state
        if !response.created.is_empty() {
            response.new_state = self.get_state(account_id, Collection::Email).await?;
            if let State::Exact(change_id) = &response.new_state {
                response.state_change = StateChange::new(account_id)
                    .with_change(DataType::Email, *change_id)
                    .with_change(DataType::Mailbox, *change_id)
                    .with_change(DataType::Thread, *change_id)
                    .into()
            }
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeReference::Value(destroy_ids).into(),
                    arguments: set::RequestArguments::Email,
                }),
            }
            .into();
        }

        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn copy_message(
        &self,
        from_account_id: u32,
        from_message_id: u32,
        account_id: u32,
        account_quota: i64,
        mailboxes: Vec<u32>,
        keywords: Vec<Keyword>,
        received_at: Option<UTCDate>,
    ) -> trc::Result<Result<IngestedEmail, SetError>> {
        // Obtain metadata
        let mut metadata = if let Some(metadata) = self
            .get_property::<Bincode<MessageMetadata>>(
                from_account_id,
                Collection::Email,
                from_message_id,
                Property::BodyStructure,
            )
            .await?
        {
            metadata.inner
        } else {
            return Ok(Err(SetError::not_found().with_description(format!(
                "Message not found not found in account {}.",
                Id::from(from_account_id)
            ))));
        };

        // Check quota
        if !self
            .has_available_quota(account_id, account_quota, metadata.size as i64)
            .await?
        {
            return Ok(Err(SetError::over_quota()));
        }

        // Set receivedAt
        if let Some(received_at) = received_at {
            metadata.received_at = received_at.timestamp() as u64;
        }

        // Obtain threadId
        let mut references = Vec::with_capacity(5);
        let mut subject = "";
        for header in &metadata.contents.parts[0].headers {
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
            size: metadata.size,
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
        let change_id = self.assign_change_id(account_id).await?;
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
            .tag(Property::ThreadId, TagValue::Id(maybe_thread_id), 0)
            .value(Property::MailboxIds, mailbox_ids, F_VALUE | F_BITMAP)
            .value(Property::Keywords, keywords, F_VALUE | F_BITMAP)
            .value(Property::Cid, change_id, F_VALUE)
            .set(
                ValueClass::FtsQueue(FtsQueueClass {
                    seq: self.generate_snowflake_id()?,
                    hash: metadata.blob_hash.clone(),
                }),
                0u64.serialize(),
            )
            .custom(EmailIndexBuilder::set(metadata));

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
        let _ = self.inner.housekeeper_tx.send(Event::IndexStart).await;

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
