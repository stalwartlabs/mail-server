/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse, RequestArguments},
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use smtp::queue;

use crate::JMAP;

impl JMAP {
    pub async fn email_submission_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::EmailId,
            Property::IdentityId,
            Property::ThreadId,
            Property::Envelope,
            Property::SendAt,
            Property::UndoStatus,
            Property::DeliveryStatus,
            Property::DsnBlobIds,
            Property::MdnBlobIds,
        ]);
        let account_id = request.account_id.document_id();
        let email_submission_ids = self
            .get_document_ids(account_id, Collection::EmailSubmission)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            email_submission_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, Collection::EmailSubmission)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the email_submission object
            let document_id = id.document_id();
            if !email_submission_ids.contains(document_id) {
                response.not_found.push(id.into());
                continue;
            }
            let mut push = if let Some(push) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                push
            } else {
                response.not_found.push(id.into());
                continue;
            };

            // Obtain queueId
            let queued_message = self
                .smtp
                .read_message(push.get(&Property::MessageId).as_uint().unwrap_or(u64::MAX))
                .await;

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::DeliveryStatus => {
                        match (queued_message.as_ref(), push.remove(property)) {
                            (Some(message), Value::Object(mut status)) => {
                                for rcpt in &message.recipients {
                                    status.set(
                                        Property::_T(rcpt.address.clone()),
                                        Object::with_capacity(3)
                                            .with_property(
                                                Property::Delivered,
                                                match &rcpt.status {
                                                    queue::Status::Scheduled
                                                    | queue::Status::TemporaryFailure(_) => {
                                                        "queued"
                                                    }
                                                    queue::Status::Completed(_) => "yes",
                                                    queue::Status::PermanentFailure(_) => "no",
                                                },
                                            )
                                            .with_property(
                                                Property::SmtpReply,
                                                match &rcpt.status {
                                                    queue::Status::Completed(reply) => reply
                                                        .response
                                                        .to_string()
                                                        .replace('\n', " "),
                                                    queue::Status::TemporaryFailure(reply)
                                                    | queue::Status::PermanentFailure(reply) => {
                                                        reply
                                                            .response
                                                            .to_string()
                                                            .replace('\n', " ")
                                                    }
                                                    queue::Status::Scheduled => {
                                                        "250 2.1.5 Queued".to_string()
                                                    }
                                                },
                                            )
                                            .with_property(Property::Displayed, "unknown"),
                                    );
                                }

                                Value::Object(status)
                            }
                            (_, value) => value,
                        }
                    }
                    Property::UndoStatus => {
                        if queued_message.is_some() {
                            Value::Text("pending".to_string())
                        } else {
                            push.remove(property)
                        }
                    }
                    Property::EmailId
                    | Property::IdentityId
                    | Property::ThreadId
                    | Property::Envelope
                    | Property::SendAt => push.remove(property),
                    Property::MdnBlobIds | Property::DsnBlobIds => Value::List(vec![]),
                    _ => Value::Null,
                };

                result.append(property.clone(), value);
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
