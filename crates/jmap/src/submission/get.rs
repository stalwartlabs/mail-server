/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::submission::{
    ArchivedAddress, ArchivedEmailSubmission, ArchivedEnvelope, Delivered, DeliveryStatus,
    UndoStatus,
};
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
use store::{rkyv::option::ArchivedOption, write::ArchivedValue};
use trc::AddContext;
use utils::map::vec_map::VecMap;

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
            let submission_ = if let Some(submission) = self
                .get_property::<ArchivedValue<ArchivedEmailSubmission>>(
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
            let submission = submission_.unarchive().caused_by(trc::location!())?;

            // Obtain queueId
            let mut delivery_status = submission
                .delivery_status
                .iter()
                .map(|(k, v)| (k.to_string(), DeliveryStatus::from(v)))
                .collect::<VecMap<_, _>>();
            let mut is_pending = false;
            if let Some(queue_id) = submission.queue_id.as_ref().map(u64::from) {
                if let Some(mut queued_message) = self.read_message(queue_id).await {
                    for rcpt in std::mem::take(&mut queued_message.recipients) {
                        *delivery_status.get_mut_or_insert(rcpt.address_lcase) = DeliveryStatus {
                            smtp_reply: match &rcpt.status {
                                queue::Status::Completed(reply) => {
                                    reply.response.to_string().replace('\n', " ")
                                }
                                queue::Status::TemporaryFailure(reply)
                                | queue::Status::PermanentFailure(reply) => {
                                    reply.response.to_string().replace('\n', " ")
                                }
                                queue::Status::Scheduled => "250 2.1.5 Queued".to_string(),
                            },
                            delivered: match &rcpt.status {
                                queue::Status::Scheduled | queue::Status::TemporaryFailure(_) => {
                                    Delivered::Queued
                                }
                                queue::Status::Completed(_) => Delivered::Yes,
                                queue::Status::PermanentFailure(_) => Delivered::No,
                            },
                            displayed: false,
                        };
                    }
                    is_pending = true;
                }
            }

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::DeliveryStatus => {
                        let mut status = Object::with_capacity(delivery_status.len());

                        for (rcpt, delivery_status) in std::mem::take(&mut delivery_status) {
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
                    Property::UndoStatus => Value::Text(
                        {
                            if is_pending {
                                UndoStatus::Pending.as_str()
                            } else {
                                submission.undo_status.as_str()
                            }
                        }
                        .to_string(),
                    ),
                    Property::EmailId => Value::Id(Id::from_parts(
                        u32::from(submission.thread_id),
                        u32::from(submission.email_id),
                    )),
                    Property::IdentityId => Value::Id(Id::from(u32::from(submission.identity_id))),
                    Property::ThreadId => Value::Id(Id::from(u32::from(submission.thread_id))),
                    Property::Envelope => build_envelope(&submission.envelope),
                    Property::SendAt => {
                        Value::Date(UTCDate::from_timestamp(u64::from(submission.send_at) as i64))
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

fn build_envelope(envelope: &ArchivedEnvelope) -> Value {
    Object::with_capacity(2)
        .with_property(Property::MailFrom, build_address(&envelope.mail_from))
        .with_property(
            Property::RcptTo,
            Value::List(envelope.rcpt_to.iter().map(build_address).collect()),
        )
        .into()
}

fn build_address(envelope: &ArchivedAddress) -> Value {
    Object::with_capacity(2)
        .with_property(Property::Email, Value::Text(envelope.email.to_string()))
        .with_property(
            Property::Parameters,
            if let ArchivedOption::Some(params) = &envelope.parameters {
                Value::Object(Object(
                    params
                        .iter()
                        .map(|(k, v)| (Property::_T(k.to_string()), v.into()))
                        .collect(),
                ))
            } else {
                Value::Null
            },
        )
        .into()
}
