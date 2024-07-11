/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashMap, sync::Arc};

use common::listener::{stream::NullIo, ServerInstance};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{self, SetRequest, SetResponse},
    object::{
        email_submission::SetArguments,
        index::{IndexAs, IndexProperty, ObjectIndexBuilder},
        Object,
    },
    request::{
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeReference,
        Call, RequestMethod,
    },
    response::references::EvalObjectReferences,
    types::{
        collection::Collection,
        date::UTCDate,
        property::Property,
        value::{MaybePatchValue, SetValue, Value},
    },
};
use mail_parser::{HeaderName, HeaderValue};
use smtp::core::{Session, SessionData, State};
use smtp_proto::{request::parser::Rfc5321Parser, MailFrom, RcptTo};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, now, BatchBuilder, Bincode};
use utils::map::vec_map::VecMap;

use crate::{email::metadata::MessageMetadata, identity::set::sanitize_email, JMAP};

pub static SCHEMA: &[IndexProperty] = &[
    IndexProperty::new(Property::UndoStatus).index_as(IndexAs::Text {
        tokenize: false,
        index: true,
    }),
    IndexProperty::new(Property::EmailId).index_as(IndexAs::LongInteger),
    IndexProperty::new(Property::IdentityId).index_as(IndexAs::Integer),
    IndexProperty::new(Property::ThreadId).index_as(IndexAs::Integer),
    IndexProperty::new(Property::SendAt).index_as(IndexAs::LongInteger),
];

impl JMAP {
    pub async fn email_submission_set(
        &self,
        mut request: SetRequest<SetArguments>,
        instance: &Arc<ServerInstance>,
        next_call: &mut Option<Call<RequestMethod>>,
    ) -> trc::Result<SetResponse> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy();

        // Process creates
        let mut changes = ChangeLogBuilder::new();
        let mut success_email_ids = HashMap::new();
        for (id, object) in request.unwrap_create() {
            match self
                .send_message(account_id, &response, instance, object)
                .await?
            {
                Ok(submission) => {
                    // Add id mapping
                    success_email_ids.insert(
                        id.clone(),
                        *submission.get(&Property::EmailId).as_id().unwrap(),
                    );

                    // Insert record
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::EmailSubmission)
                        .create_document()
                        .custom(ObjectIndexBuilder::new(SCHEMA).with_changes(submission));
                    let document_id = self.write_batch_expect_id(batch).await?;
                    changes.log_insert(Collection::EmailSubmission, document_id);
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
                .get_property::<HashedValue<Object<Value>>>(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                submission
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            let mut queue_id = u64::MAX;
            let mut undo_status = None;

            for (property, value) in object.properties {
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
                    Value::UnsignedInt(queue_id_),
                ) = (&property, value, submission.inner.get(&Property::MessageId))
                {
                    undo_status = undo_status_.into();
                    queue_id = *queue_id_;
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
                    if let Some(queue_message) = self.smtp.read_message(queue_id).await {
                        // Delete message from queue
                        let message_due = queue_message.next_event().unwrap_or_default();
                        queue_message.remove(&self.smtp, message_due).await;

                        // Update record
                        let mut batch = BatchBuilder::new();
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::EmailSubmission)
                            .update_document(document_id)
                            .custom(
                                ObjectIndexBuilder::new(SCHEMA)
                                    .with_current(submission)
                                    .with_changes(
                                        Object::with_capacity(1)
                                            .with_property(Property::UndoStatus, undo_status),
                                    ),
                            );
                        self.write_batch(batch).await?;
                        changes.log_update(Collection::EmailSubmission, document_id);
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
                .get_property::<HashedValue<Object<Value>>>(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                // Update record
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::EmailSubmission)
                    .delete_document(document_id)
                    .custom(ObjectIndexBuilder::new(SCHEMA).with_current(submission));
                self.write_batch(batch).await?;
                changes.log_delete(Collection::EmailSubmission, document_id);
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Write changes
        if !changes.is_empty() {
            response.new_state = Some(self.commit_changes(account_id, changes).await?.into());
        }

        // On success
        if (request
            .arguments
            .on_success_destroy_email
            .as_ref()
            .map_or(false, |p| !p.is_empty())
            || request
                .arguments
                .on_success_update_email
                .as_ref()
                .map_or(false, |p| !p.is_empty()))
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
    ) -> trc::Result<Result<Object<Value>, SetError>> {
        let mut submission = Object::with_capacity(object.properties.len());
        let mut email_id = u32::MAX;
        let mut identity_id = u32::MAX;
        let mut mail_from = None;
        let mut rcpt_to: Vec<RcptTo<String>> = Vec::new();

        for (property, value) in object.properties {
            let value = match response.eval_object_references(value) {
                Ok(value) => value,
                Err(err) => {
                    return Ok(Err(err));
                }
            };

            let value = match (&property, value) {
                (Property::EmailId, MaybePatchValue::Value(Value::Id(value))) => {
                    submission.append(Property::ThreadId, Value::Id(value.prefix_id().into()));
                    email_id = value.document_id();
                    Value::Id(value)
                }
                (Property::IdentityId, MaybePatchValue::Value(Value::Id(value))) => {
                    identity_id = value.document_id();
                    Value::Id(value)
                }
                (Property::Envelope, MaybePatchValue::Value(Value::Object(value))) => {
                    for (property, value) in &value.properties {
                        match (property, value) {
                            (Property::MailFrom, _) => match parse_envelope_address(value) {
                                Ok((addr, params)) => {
                                    match Rfc5321Parser::new(
                                        &mut params
                                            .as_ref()
                                            .map_or(&b"\n"[..], |p| p.as_bytes())
                                            .iter(),
                                    )
                                    .mail_from_parameters(addr)
                                    {
                                        Ok(addr) => {
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
                                        Ok((addr, params)) => {
                                            match Rfc5321Parser::new(
                                                &mut params
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
                    Value::Object(value)
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
            };

            submission.append(property, value);
        }

        // Make sure we have all required fields.
        if email_id == u32::MAX || identity_id == u32::MAX {
            return Ok(Err(SetError::invalid_properties()
                .with_properties([Property::EmailId, Property::IdentityId])
                .with_description(
                    "emailId and identityId properties are required.",
                )));
        }

        // Fetch identity's mailFrom
        let identity_mail_from = if let Some(identity_mail_from) = self
            .get_property::<Object<Value>>(
                account_id,
                Collection::Identity,
                identity_id,
                Property::Value,
            )
            .await?
            .and_then(|mut obj| obj.properties.remove(&Property::Email))
            .and_then(|value| value.try_unwrap_string())
        {
            identity_mail_from
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
            submission
                .properties
                .get_mut_or_insert_with(Property::Envelope, || {
                    Value::Object(Object::with_capacity(2))
                })
                .as_obj_mut()
                .unwrap()
                .set(
                    Property::MailFrom,
                    Object::with_capacity(1)
                        .with_property(Property::Email, identity_mail_from.clone()),
                );
            MailFrom {
                address: identity_mail_from,
                ..Default::default()
            }
        };

        // Obtain message metadata
        let metadata = if let Some(metadata) = self
            .get_property::<Bincode<MessageMetadata>>(
                account_id,
                Collection::Email,
                email_id,
                Property::BodyStructure,
            )
            .await?
        {
            metadata.inner
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::EmailId)
                .with_description("Email not found.")));
        };

        // Add recipients to envelope if missing
        if rcpt_to.is_empty() {
            let mut envelope_values = Vec::new();
            for header in &metadata.contents.parts[0].headers {
                if matches!(
                    header.name,
                    HeaderName::To | HeaderName::Cc | HeaderName::Bcc
                ) {
                    if let HeaderValue::Address(addr) = &header.value {
                        for address in addr.iter() {
                            if let Some(address) = address.address().and_then(sanitize_email) {
                                if !rcpt_to.iter().any(|rcpt| rcpt.address == address) {
                                    envelope_values.push(Value::Object(
                                        Object::with_capacity(1)
                                            .with_property(Property::Email, address.clone()),
                                    ));
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

            if !rcpt_to.is_empty() {
                submission
                    .properties
                    .get_mut_or_insert_with(Property::Envelope, || {
                        Value::Object(Object::with_capacity(1))
                    })
                    .as_obj_mut()
                    .unwrap()
                    .set(Property::RcptTo, Value::List(envelope_values));
            } else {
                return Ok(Err(SetError::new(SetErrorType::NoRecipients)
                    .with_description("No recipients found in email.")));
            }
        }

        // Update sendAt
        submission.append(
            Property::SendAt,
            UTCDate::from_timestamp(if mail_from.hold_until > 0 {
                mail_from.hold_until
            } else if mail_from.hold_for > 0 {
                mail_from.hold_for + now()
            } else {
                now()
            } as i64),
        );

        // Obtain raw message
        let message =
            if let Some(message) = self.get_blob(&metadata.blob_hash, 0..usize::MAX).await? {
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

        // Begin local SMTP session
        let mut session =
            Session::<NullIo>::local(self.smtp.clone(), instance.clone(), SessionData::default());

        // MAIL FROM
        let _ = session.handle_mail_from(mail_from).await;
        if let Some(error) = session.has_failed() {
            return Ok(Err(SetError::new(SetErrorType::ForbiddenMailFrom)
                .with_description(format!(
                    "Server rejected MAIL-FROM: {}",
                    error.trim()
                ))));
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
            if let State::Accepted(queue_id) = session.state {
                submission.append(Property::MessageId, queue_id);
            } else {
                return Ok(Err(SetError::new(SetErrorType::ForbiddenToSend)
                    .with_description(format!(
                        "Server rejected DATA: {}",
                        std::str::from_utf8(&response).unwrap().trim()
                    ))));
            }
        }

        // Set responses
        submission.append(
            Property::UndoStatus,
            if has_success { "final" } else { "failed" },
        );
        submission.append(
            Property::DeliveryStatus,
            Object {
                properties: responses
                    .into_iter()
                    .map(|(addr, response)| {
                        (
                            Property::_T(addr),
                            Value::Object(
                                Object::with_capacity(3)
                                    .with_property(
                                        Property::Delivered,
                                        if response.is_none() { "unknown" } else { "no" },
                                    )
                                    .with_property(
                                        Property::SmtpReply,
                                        response.unwrap_or_else(|| "250 2.1.5 Queued".to_string()),
                                    )
                                    .with_property(Property::Displayed, "unknown"),
                            ),
                        )
                    })
                    .collect::<VecMap<Property, Value>>(),
            },
        );

        Ok(Ok(submission))
    }
}

fn parse_envelope_address(envelope: &Value) -> Result<(String, Option<String>), SetError> {
    if let Value::Object(envelope) = envelope {
        if let Some(Value::Text(addr)) = envelope.properties.get(&Property::Email) {
            if let Some(addr) = sanitize_email(addr) {
                if let Some(Value::Object(params)) = envelope.properties.get(&Property::Parameters)
                {
                    let mut params_text = String::new();
                    for (k, v) in params.properties.iter() {
                        if let Property::_T(k) = &k {
                            if !k.is_empty() {
                                if !params_text.is_empty() {
                                    params_text.push(' ');
                                }
                                params_text.push_str(k);
                                if let Value::Text(v) = v {
                                    params_text.push('=');
                                    params_text.push_str(v);
                                }
                            }
                        }
                    }
                    params_text.push('\n');

                    Ok((addr, Some(params_text)))
                } else {
                    Ok((addr, None))
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
