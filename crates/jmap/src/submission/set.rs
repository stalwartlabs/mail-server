/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashMap, sync::Arc};

use common::{
    Server,
    listener::{ServerInstance, stream::NullIo},
    storage::index::ObjectIndexBuilder,
};

use email::{
    identity::Identity,
    message::metadata::MessageMetadata,
    submission::{Address, Delivered, DeliveryStatus, EmailSubmission, UndoStatus},
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{self, SetRequest, SetResponse},
    object::email_submission::SetArguments,
    request::{
        Call, RequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeReference,
    },
    response::references::EvalObjectReferences,
    types::{
        collection::Collection,
        id::Id,
        property::Property,
        state::State,
        value::{MaybePatchValue, Object, SetValue, Value},
    },
};
use mail_parser::{ArchivedHeaderName, ArchivedHeaderValue};
use smtp::{
    core::{Session, SessionData},
    queue::spool::SmtpSpool,
};
use smtp_proto::{MailFrom, RcptTo, request::parser::Rfc5321Parser};
use store::write::{BatchBuilder, now};
use trc::AddContext;
use utils::{BlobHash, map::vec_map::VecMap, sanitize_email};

use crate::blob::download::BlobDownload;
use std::future::Future;

pub trait EmailSubmissionSet: Sync + Send {
    fn email_submission_set(
        &self,
        request: SetRequest<SetArguments>,
        instance: &Arc<ServerInstance>,
        next_call: &mut Option<Call<RequestMethod>>,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;

    fn send_message(
        &self,
        account_id: u32,
        response: &SetResponse,
        instance: &Arc<ServerInstance>,
        object: Object<SetValue>,
    ) -> impl Future<Output = trc::Result<Result<EmailSubmission, SetError>>> + Send;
}

impl EmailSubmissionSet for Server {
    async fn email_submission_set(
        &self,
        mut request: SetRequest<SetArguments>,
        instance: &Arc<ServerInstance>,
        next_call: &mut Option<Call<RequestMethod>>,
    ) -> trc::Result<SetResponse> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy();

        // Process creates
        let mut success_email_ids = HashMap::new();
        let mut batch = BatchBuilder::new();
        for (id, object) in request.unwrap_create() {
            match self
                .send_message(account_id, &response, instance, object)
                .await?
            {
                Ok(submission) => {
                    // Add id mapping
                    success_email_ids.insert(
                        id.clone(),
                        Id::from_parts(submission.thread_id, submission.email_id),
                    );

                    // Insert record
                    let document_id = self
                        .store()
                        .assign_document_ids(account_id, Collection::EmailSubmission, 1)
                        .await
                        .caused_by(trc::location!())?;
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::EmailSubmission)
                        .create_document(document_id)
                        .custom(ObjectIndexBuilder::<(), _>::new().with_changes(submission))
                        .caused_by(trc::location!())?
                        .commit_point();
                    response.created(id, document_id);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                }
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain submission
            let document_id = id.document_id();
            let submission = if let Some(submission) = self
                .get_archive(account_id, Collection::EmailSubmission, document_id)
                .await?
            {
                submission
                    .into_deserialized::<EmailSubmission>()
                    .caused_by(trc::location!())?
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            let mut queue_id = u64::MAX;
            let mut undo_status = None;

            for (property, value) in object.0 {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };
                if let (
                    Property::UndoStatus,
                    MaybePatchValue::Value(Value::Text(undo_status_)),
                    Some(queue_id_),
                ) = (&property, value, submission.inner.queue_id)
                {
                    undo_status = undo_status_.into();
                    queue_id = queue_id_;
                } else {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(property)
                            .with_description("Field could not be set."),
                    );
                    continue 'update;
                }
            }

            match undo_status {
                Some(undo_status) if undo_status == "canceled" => {
                    if let Some(queue_message) = self.read_message(queue_id).await {
                        // Delete message from queue
                        let message_due = queue_message.next_event().unwrap_or_default();
                        queue_message.remove(self, message_due).await;

                        // Update record
                        let mut new_submission = submission.inner.clone();
                        new_submission.undo_status = UndoStatus::Canceled;
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::EmailSubmission)
                            .update_document(document_id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(submission)
                                    .with_changes(new_submission),
                            )
                            .caused_by(trc::location!())?
                            .commit_point();
                        response.updated.append(id, None);
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::new(SetErrorType::CannotUnsend).with_description(
                                "The requested message is no longer in the queue.",
                            ),
                        );
                    }
                }
                Some(_) => {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::UndoStatus)
                            .with_description("Email submissions can only be cancelled."),
                    );
                }
                None => {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_description("No properties to set were found."),
                    );
                }
            }
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if let Some(submission) = self
                .get_archive(account_id, Collection::EmailSubmission, document_id)
                .await?
            {
                // Update record
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::EmailSubmission)
                    .delete_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new().with_current(
                            submission
                                .to_unarchived::<EmailSubmission>()
                                .caused_by(trc::location!())?,
                        ),
                    )
                    .caused_by(trc::location!())?
                    .commit_point();
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;
            response.new_state = State::Exact(change_id).into();
        }

        // On success
        if (request
            .arguments
            .on_success_destroy_email
            .as_ref()
            .is_some_and(|p| !p.is_empty())
            || request
                .arguments
                .on_success_update_email
                .as_ref()
                .is_some_and(|p| !p.is_empty()))
            && response.has_changes()
        {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequest {
                    account_id: request.account_id,
                    if_in_state: None,
                    create: None,
                    update: request.arguments.on_success_update_email.map(|update| {
                        update
                            .into_iter()
                            .filter_map(|(id, value)| {
                                (
                                    match id {
                                        MaybeReference::Value(id) => id,
                                        MaybeReference::Reference(id_ref) => {
                                            *(success_email_ids.get(&id_ref)?)
                                        }
                                    },
                                    value,
                                )
                                    .into()
                            })
                            .collect()
                    }),
                    destroy: request.arguments.on_success_destroy_email.map(|ids| {
                        MaybeReference::Value(
                            ids.into_iter()
                                .filter_map(|id| match id {
                                    MaybeReference::Value(id) => Some(id),
                                    MaybeReference::Reference(id_ref) => {
                                        success_email_ids.get(&id_ref).copied()
                                    }
                                })
                                .collect(),
                        )
                    }),
                    arguments: set::RequestArguments::Email,
                }),
            }
            .into();
        }

        Ok(response)
    }

    async fn send_message(
        &self,
        account_id: u32,
        response: &SetResponse,
        instance: &Arc<ServerInstance>,
        object: Object<SetValue>,
    ) -> trc::Result<Result<EmailSubmission, SetError>> {
        let mut submission = EmailSubmission {
            email_id: u32::MAX,
            identity_id: u32::MAX,
            thread_id: u32::MAX,
            ..Default::default()
        };
        let mut mail_from: Option<MailFrom<String>> = None;
        let mut rcpt_to: Vec<RcptTo<String>> = Vec::new();

        for (property, value) in object.0 {
            let value = match response.eval_object_references(value) {
                Ok(value) => value,
                Err(err) => {
                    return Ok(Err(err));
                }
            };

            match (&property, value) {
                (Property::EmailId, MaybePatchValue::Value(Value::Id(value))) => {
                    submission.email_id = value.document_id();
                    submission.thread_id = value.prefix_id();
                }
                (Property::IdentityId, MaybePatchValue::Value(Value::Id(value))) => {
                    submission.identity_id = value.document_id();
                }
                (Property::Envelope, MaybePatchValue::Value(Value::Object(value))) => {
                    for (property, value) in value.0 {
                        match (&property, value) {
                            (Property::MailFrom, value) => match parse_envelope_address(value) {
                                Ok((addr, params, smtp_params)) => {
                                    match Rfc5321Parser::new(
                                        &mut smtp_params
                                            .as_ref()
                                            .map_or(&b"\n"[..], |p| p.as_bytes())
                                            .iter(),
                                    )
                                    .mail_from_parameters(addr)
                                    {
                                        Ok(addr) => {
                                            submission.envelope.mail_from = Address {
                                                email: addr.address.clone(),
                                                parameters: params,
                                            };
                                            mail_from = addr.into();
                                        }
                                        Err(err) => {
                                            return Ok(Err(SetError::invalid_properties()
                                                .with_property(Property::Envelope)
                                                .with_description(format!(
                                                    "Failed to parse mailFrom parameters: {err}."
                                                ))));
                                        }
                                    }
                                }
                                Err(err) => {
                                    return Ok(Err(err));
                                }
                            },
                            (Property::RcptTo, Value::List(value)) => {
                                for addr in value {
                                    match parse_envelope_address(addr) {
                                        Ok((addr, params, smtp_params)) => {
                                            match Rfc5321Parser::new(
                                                &mut smtp_params
                                                    .as_ref()
                                                    .map_or(&b"\n"[..], |p| p.as_bytes())
                                                    .iter(),
                                            )
                                            .rcpt_to_parameters(addr)
                                            {
                                                Ok(addr) => {
                                                    if !rcpt_to
                                                        .iter()
                                                        .any(|rcpt| rcpt.address == addr.address)
                                                    {
                                                        submission.envelope.rcpt_to.push(Address {
                                                            email: addr.address.clone(),
                                                            parameters: params,
                                                        });
                                                        rcpt_to.push(addr);
                                                    }
                                                }
                                                Err(err) => {
                                                    return Ok(Err(SetError::invalid_properties()
                                                        .with_property(Property::Envelope)
                                                        .with_description(format!(
                                                        "Failed to parse rcptTo parameters: {err}."
                                                    ))));
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            return Ok(Err(err));
                                        }
                                    }
                                }
                            }
                            _ => {
                                return Ok(Err(SetError::invalid_properties()
                                    .with_property(Property::Envelope)
                                    .with_description(format!(
                                        "Invalid object property {property}."
                                    ))));
                            }
                        }
                    }
                }
                (Property::Envelope, MaybePatchValue::Value(Value::Null)) => {
                    continue;
                }
                (Property::UndoStatus, MaybePatchValue::Value(Value::Text(_))) => continue,
                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property)
                        .with_description("Field could not be set.")));
                }
            }
        }

        // Make sure we have all required fields.
        if submission.email_id == u32::MAX || submission.identity_id == u32::MAX {
            return Ok(Err(SetError::invalid_properties()
                .with_properties([Property::EmailId, Property::IdentityId])
                .with_description(
                    "emailId and identityId properties are required.",
                )));
        }

        // Fetch identity's mailFrom
        let identity_mail_from = if let Some(identity) = self
            .get_archive(account_id, Collection::Identity, submission.identity_id)
            .await?
        {
            identity
                .unarchive::<Identity>()
                .caused_by(trc::location!())?
                .email
                .to_string()
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::IdentityId)
                .with_description("Identity not found.")));
        };

        // Make sure the envelope address matches the identity email address
        let mail_from = if let Some(mail_from) = mail_from {
            if !mail_from.address.eq_ignore_ascii_case(&identity_mail_from) {
                return Ok(Err(SetError::new(SetErrorType::ForbiddenFrom)
                    .with_description(
                        "Envelope mailFrom does not match identity email address.",
                    )));
            }
            mail_from
        } else {
            submission.envelope.mail_from = Address {
                email: identity_mail_from.clone(),
                parameters: None,
            };
            MailFrom {
                address: identity_mail_from,
                ..Default::default()
            }
        };

        // Obtain message metadata
        let metadata_ = if let Some(metadata) = self
            .get_archive_by_property(
                account_id,
                Collection::Email,
                submission.email_id,
                Property::BodyStructure,
            )
            .await?
        {
            metadata
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::EmailId)
                .with_description("Email not found.")));
        };
        let metadata = metadata_
            .unarchive::<MessageMetadata>()
            .caused_by(trc::location!())?;

        // Add recipients to envelope if missing
        let mut bcc_header = None;
        if rcpt_to.is_empty() {
            for header in metadata.contents[0].parts[0].headers.iter() {
                if matches!(
                    header.name,
                    ArchivedHeaderName::To | ArchivedHeaderName::Cc | ArchivedHeaderName::Bcc
                ) {
                    if matches!(header.name, ArchivedHeaderName::Bcc) {
                        bcc_header = Some(header);
                    }
                    if let ArchivedHeaderValue::Address(addr) = &header.value {
                        for address in addr.iter() {
                            if let Some(address) = address.address().and_then(sanitize_email) {
                                if !rcpt_to.iter().any(|rcpt| rcpt.address == address) {
                                    submission.envelope.rcpt_to.push(Address {
                                        email: address.to_string(),
                                        parameters: None,
                                    });
                                    rcpt_to.push(RcptTo {
                                        address,
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }

            if rcpt_to.is_empty() {
                return Ok(Err(SetError::new(SetErrorType::NoRecipients)
                    .with_description("No recipients found in email.")));
            }
        } else {
            bcc_header = metadata.contents[0].parts[0]
                .headers
                .iter()
                .find(|header| matches!(header.name, ArchivedHeaderName::Bcc));
        }

        // Update sendAt
        submission.send_at = if mail_from.hold_until > 0 {
            mail_from.hold_until
        } else if mail_from.hold_for > 0 {
            mail_from.hold_for + now()
        } else {
            now()
        };

        // Obtain raw message
        let mut message = if let Some(message) = self
            .get_blob(&BlobHash::from(&metadata.blob_hash), 0..usize::MAX)
            .await?
        {
            if message.len() > self.core.jmap.mail_max_size {
                return Ok(Err(SetError::new(SetErrorType::InvalidEmail)
                    .with_description(format!(
                        "Message exceeds maximum size of {} bytes.",
                        self.core.jmap.mail_max_size
                    ))));
            }

            message
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::EmailId)
                .with_description("Blob for email not found.")));
        };

        // Remove BCC header if present
        if let Some(bcc_header) = bcc_header {
            let mut new_message = Vec::with_capacity(message.len());
            new_message.extend_from_slice(&message[..u32::from(bcc_header.offset_field) as usize]);
            new_message.extend_from_slice(&message[u32::from(bcc_header.offset_end) as usize..]);
            message = new_message;
        }

        // Begin local SMTP session
        let mut session = Session::<NullIo>::local(
            self.clone(),
            instance.clone(),
            SessionData::local(
                self.get_access_token(account_id)
                    .await
                    .caused_by(trc::location!())?,
                None,
                vec![],
                vec![],
                0,
            ),
        );

        // Spawn SMTP session to avoid overflowing the stack
        let handle = tokio::spawn(async move {
            // MAIL FROM
            let _ = session.handle_mail_from(mail_from).await;
            if let Some(error) = session.has_failed() {
                return Err(SetError::new(SetErrorType::ForbiddenMailFrom)
                    .with_description(format!("Server rejected MAIL-FROM: {}", error.trim())));
            }

            // RCPT TO
            let mut responses = Vec::new();
            let mut has_success = false;
            for rcpt in rcpt_to {
                let addr = rcpt.address.clone();
                let _ = session.handle_rcpt_to(rcpt).await;
                let response = session.has_failed();
                if response.is_none() {
                    has_success = true;
                }
                responses.push((addr, response));
            }

            // DATA
            if has_success {
                session.data.message = message;
                let response = session.queue_message().await;
                if let smtp::core::State::Accepted(queue_id) = session.state {
                    Ok((true, responses, Some(queue_id)))
                } else {
                    Err(
                        SetError::new(SetErrorType::ForbiddenToSend).with_description(format!(
                            "Server rejected DATA: {}",
                            std::str::from_utf8(&response).unwrap().trim()
                        )),
                    )
                }
            } else {
                Ok((false, responses, None))
            }
        });

        match handle.await {
            Ok(Ok((has_success, responses, queue_id))) => {
                // Set queue ID
                if let Some(queue_id) = queue_id {
                    submission.queue_id = Some(queue_id);
                }

                // Set responses
                submission.undo_status = if has_success {
                    UndoStatus::Final
                } else {
                    UndoStatus::Pending
                };
                submission.delivery_status = responses
                    .into_iter()
                    .map(|(addr, response)| {
                        (
                            addr.to_string(),
                            DeliveryStatus {
                                delivered: if response.is_none() {
                                    Delivered::Unknown
                                } else {
                                    Delivered::No
                                },
                                smtp_reply: response
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| "250 2.1.5 Queued".to_string()),
                                displayed: false,
                            },
                        )
                    })
                    .collect();

                Ok(Ok(submission))
            }
            Ok(Err(err)) => Ok(Err(err)),
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
                .details("Join Error")),
        }
    }
}

#[allow(clippy::type_complexity)]
fn parse_envelope_address(
    envelope: Value,
) -> Result<
    (
        String,
        Option<VecMap<String, Option<String>>>,
        Option<String>,
    ),
    SetError,
> {
    if let Value::Object(mut envelope) = envelope {
        if let Some(Value::Text(addr)) = envelope.0.remove(&Property::Email) {
            if let Some(addr) = sanitize_email(&addr) {
                if let Some(Value::Object(params)) = envelope.0.remove(&Property::Parameters) {
                    let mut params_text = String::new();
                    let mut params_list = VecMap::with_capacity(params.0.len());

                    for (k, v) in params.0 {
                        if let Property::_T(k) = k {
                            if !k.is_empty() {
                                if !params_text.is_empty() {
                                    params_text.push(' ');
                                }
                                params_text.push_str(&k);
                                if let Value::Text(v) = v {
                                    params_text.push('=');
                                    params_text.push_str(&v);
                                    params_list.append(k, Some(v));
                                } else {
                                    params_list.append(k, None);
                                }
                            }
                        }
                    }
                    params_text.push('\n');

                    Ok((addr.to_string(), Some(params_list), Some(params_text)))
                } else {
                    Ok((addr.to_string(), None, None))
                }
            } else {
                Err(SetError::invalid_properties()
                    .with_property(Property::Envelope)
                    .with_description(format!("Invalid e-mail address {addr:?}.")))
            }
        } else {
            Err(SetError::invalid_properties()
                .with_property(Property::Envelope)
                .with_description("Missing e-mail address field."))
        }
    } else {
        Err(SetError::invalid_properties()
            .with_property(Property::Envelope)
            .with_description("Invalid envelope object."))
    }
}
