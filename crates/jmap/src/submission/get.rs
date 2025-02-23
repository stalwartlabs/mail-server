/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::submission::{Address, Delivered, EmailSubmission, Envelope, UndoStatus};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        collection::Collection,
        date::UTCDate,
        id::Id,
        property::Property,
        value::{Object, Value},
    },
};
use smtp::queue::{self, spool::SmtpSpool};
use std::future::Future;

use crate::changes::state::StateManager;

pub trait EmailSubmissionGet: Sync + Send {
    fn email_submission_get(
        &self,
        request: GetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;
}

impl EmailSubmissionGet for Server {
    async fn email_submission_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
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
            let mut submission = if let Some(submission) = self
                .get_property::<EmailSubmission>(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                submission
            } else {
                response.not_found.push(id.into());
                continue;
            };

            // Obtain queueId
            if let Some(queue_id) = submission.queue_id {
                if let Some(mut queued_message) = self.read_message(queue_id).await {
                    for rcpt in std::mem::take(&mut queued_message.recipients) {
                        let rcpt_status = submission
                            .delivery_status
                            .get_mut_or_insert(rcpt.address_lcase);
                        rcpt_status.delivered = match &rcpt.status {
                            queue::Status::Scheduled | queue::Status::TemporaryFailure(_) => {
                                Delivered::Queued
                            }
                            queue::Status::Completed(_) => Delivered::Yes,
                            queue::Status::PermanentFailure(_) => Delivered::No,
                        };
                        rcpt_status.smtp_reply = match &rcpt.status {
                            queue::Status::Completed(reply) => {
                                reply.response.to_string().replace('\n', " ")
                            }
                            queue::Status::TemporaryFailure(reply)
                            | queue::Status::PermanentFailure(reply) => {
                                reply.response.to_string().replace('\n', " ")
                            }
                            queue::Status::Scheduled => "250 2.1.5 Queued".to_string(),
                        };
                    }
                    submission.undo_status = UndoStatus::Pending;
                }
            }

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::DeliveryStatus => {
                        let mut status = Object::with_capacity(submission.delivery_status.len());

                        for (rcpt, delivery_status) in
                            std::mem::take(&mut submission.delivery_status)
                        {
                            status.set(
                                Property::_T(rcpt),
                                Object::with_capacity(3)
                                    .with_property(
                                        Property::Delivered,
                                        delivery_status.delivered.as_str().to_string(),
                                    )
                                    .with_property(Property::SmtpReply, delivery_status.smtp_reply)
                                    .with_property(Property::Displayed, "unknown"),
                            );
                        }

                        Value::Object(status)
                    }
                    Property::UndoStatus => {
                        Value::Text(submission.undo_status.as_str().to_string())
                    }
                    Property::EmailId => {
                        Value::Id(Id::from_parts(submission.thread_id, submission.email_id))
                    }
                    Property::IdentityId => Value::Id(Id::from(submission.identity_id)),
                    Property::ThreadId => Value::Id(Id::from(submission.thread_id)),
                    Property::Envelope => build_envelope(std::mem::take(&mut submission.envelope)),
                    Property::SendAt => {
                        Value::Date(UTCDate::from_timestamp(submission.send_at as i64))
                    }
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

fn build_envelope(envelope: Envelope) -> Value {
    Object::with_capacity(2)
        .with_property(Property::MailFrom, build_address(envelope.mail_from))
        .with_property(
            Property::RcptTo,
            Value::List(envelope.rcpt_to.into_iter().map(build_address).collect()),
        )
        .into()
}

fn build_address(envelope: Address) -> Value {
    Object::with_capacity(2)
        .with_property(Property::Email, Value::Text(envelope.email))
        .with_property(
            Property::Parameters,
            if let Some(params) = envelope.parameters {
                Value::Object(Object(
                    params
                        .into_iter()
                        .map(|(k, v)| (Property::_T(k), v.into()))
                        .collect(),
                ))
            } else {
                Value::Null
            },
        )
        .into()
}
