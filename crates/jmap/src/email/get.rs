/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse},
    object::{email::GetArguments, Object},
    types::{
        acl::Acl, blob::BlobId, collection::Collection, id::Id, keyword::Keyword,
        property::Property, value::Value,
    },
};
use mail_parser::Message;

use crate::{auth::AccessToken, email::headers::HeaderToValue, JMAP};

use super::body::{ToBodyPart, TruncateBody};

impl JMAP {
    pub async fn email_get(
        &self,
        mut request: GetRequest<GetArguments>,
        access_token: &AccessToken,
    ) -> Result<GetResponse, MethodError> {
        let ids = request.unwrap_ids(self.config.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::BlobId,
            Property::ThreadId,
            Property::MailboxIds,
            Property::Keywords,
            Property::Size,
            Property::ReceivedAt,
            Property::MessageId,
            Property::InReplyTo,
            Property::References,
            Property::Sender,
            Property::From,
            Property::To,
            Property::Cc,
            Property::Bcc,
            Property::ReplyTo,
            Property::Subject,
            Property::SentAt,
            Property::HasAttachment,
            Property::Preview,
            Property::BodyValues,
            Property::TextBody,
            Property::HtmlBody,
            Property::Attachments,
        ]);
        let body_properties = request.arguments.body_properties.unwrap_or_else(|| {
            vec![
                Property::PartId,
                Property::BlobId,
                Property::Size,
                Property::Name,
                Property::Type,
                Property::Charset,
                Property::Disposition,
                Property::Cid,
                Property::Language,
                Property::Location,
            ]
        });
        let fetch_text_body_values = request.arguments.fetch_text_body_values.unwrap_or(false);
        let fetch_html_body_values = request.arguments.fetch_html_body_values.unwrap_or(false);
        let fetch_all_body_values = request.arguments.fetch_all_body_values.unwrap_or(false);
        let max_body_value_bytes = request.arguments.max_body_value_bytes.unwrap_or(0);

        let account_id = request.account_id.document_id();
        let message_ids = self
            .owned_or_shared_messages(access_token, account_id, Acl::ReadItems)
            .await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            let document_ids = message_ids
                .iter()
                .take(self.config.get_max_objects)
                .collect::<Vec<_>>();
            self.get_properties::<u32>(
                account_id,
                Collection::Email,
                document_ids.iter().copied(),
                Property::ThreadId,
            )
            .await?
            .into_iter()
            .zip(document_ids)
            .filter_map(|(thread_id, document_id)| Id::from_parts(thread_id?, document_id).into())
            .collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self.get_state(account_id, Collection::Email).await?.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        // Check if we need to fetch the raw headers or body
        let mut needs_headers = false;
        let mut needs_body = false;
        for property in &properties {
            match property {
                Property::Header(_) | Property::Headers => {
                    needs_headers = true;
                }
                Property::BodyValues
                | Property::TextBody
                | Property::HtmlBody
                | Property::Attachments
                | Property::BodyStructure => {
                    needs_body = true;
                }
                _ => (),
            }

            if needs_body {
                break;
            }
        }

        'outer: for id in ids {
            // Obtain the email object
            if !message_ids.contains(id.document_id()) {
                response.not_found.push(id);
                continue;
            }
            let mut values = match self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::Email,
                    id.document_id(),
                    &Property::BodyStructure,
                )
                .await?
            {
                Some(values) => values,
                None => {
                    response.not_found.push(id);
                    continue;
                }
            };

            // Retrieve raw message if needed
            let blob_id = BlobId::maildir(account_id, id.document_id());
            let raw_message = if needs_body || needs_headers {
                let offset = if !needs_body {
                    blob_id
                        .section
                        .as_ref()
                        .map(|s| s.offset_start as u32)
                        .unwrap_or(u32::MAX)
                } else {
                    u32::MAX
                };

                if let Some(raw_message) = self.get_blob(&blob_id.kind, 0..offset).await? {
                    raw_message
                } else {
                    tracing::warn!(event = "not-found",
                        account_id = account_id,
                        collection = ?Collection::Email,
                        document_id = id.document_id(),
                        blob_id = ?blob_id,
                        "Blob not found");
                    response.not_found.push(id);
                    continue;
                }
            } else {
                vec![]
            };
            let message = if !raw_message.is_empty() {
                let message = Message::parse(&raw_message);
                if message.is_none() {
                    tracing::warn!(
                        event = "parse-error",
                        account_id = account_id,
                        collection = ?Collection::Email,
                        document_id = id.document_id(),
                        blob_id = ?blob_id,
                        "Failed to parse stored message");
                }
                message
            } else {
                None
            };

            // Prepare response
            let mut email = Object::with_capacity(properties.len());
            for property in &properties {
                match property {
                    Property::Id => {
                        email.append(Property::Id, Id::from(*id));
                    }
                    Property::ThreadId => {
                        email.append(Property::ThreadId, Id::from(id.prefix_id()));
                    }
                    Property::BlobId => {
                        email.append(Property::BlobId, blob_id.clone());
                    }
                    Property::MailboxIds => {
                        if let Some(mailboxes) = self
                            .get_property::<Vec<u32>>(
                                account_id,
                                Collection::Email,
                                id.document_id(),
                                &Property::MailboxIds,
                            )
                            .await?
                            .map(|ids| {
                                let mut obj = Object::with_capacity(ids.len());
                                for id in ids {
                                    obj.append(Property::_T(Id::from(id).to_string()), true);
                                }
                                Value::Object(obj)
                            })
                        {
                            email.append(property.clone(), mailboxes);
                        } else {
                            tracing::debug!(event = "not-found",
                                            account_id = account_id,
                                            collection = ?Collection::Email,
                                            document_id = id.document_id(),
                                            "Mailbox property not found");
                            response.not_found.push(id);
                            continue 'outer;
                        }
                    }
                    Property::Keywords => {
                        if let Some(keywords) = self
                            .get_property::<Vec<Keyword>>(
                                account_id,
                                Collection::Email,
                                id.document_id(),
                                &Property::Keywords,
                            )
                            .await?
                            .map(|keywords| {
                                let mut obj = Object::with_capacity(keywords.len());
                                for keyword in keywords {
                                    obj.append(Property::_T(keyword.to_string()), true);
                                }
                                Value::Object(obj)
                            })
                        {
                            email.append(property.clone(), keywords);
                        } else {
                            tracing::debug!(event = "not-found",
                                account_id = account_id,
                                collection = ?Collection::Email,
                                document_id = id.document_id(),
                                "Keywords property not found");
                            response.not_found.push(id);
                            continue 'outer;
                        }
                    }
                    Property::Size
                    | Property::ReceivedAt
                    | Property::MessageId
                    | Property::InReplyTo
                    | Property::References
                    | Property::Sender
                    | Property::From
                    | Property::To
                    | Property::Cc
                    | Property::Bcc
                    | Property::ReplyTo
                    | Property::Subject
                    | Property::SentAt
                    | Property::HasAttachment
                    | Property::Preview => {
                        email.append(property.clone(), values.remove(property));
                    }
                    Property::Header(_) => {
                        if let Some(message) = &message {
                            email.append(
                                property.clone(),
                                message.parts[0].header_to_value(property, &raw_message),
                            );
                        }
                    }
                    Property::Headers => {
                        if let Some(message) = &message {
                            email.append(
                                Property::Headers,
                                message.parts[0].headers_to_value(&raw_message),
                            );
                        }
                    }
                    Property::TextBody | Property::HtmlBody | Property::Attachments => {
                        if let Some(message) = &message {
                            let list = match property {
                                Property::TextBody => &message.text_body,
                                Property::HtmlBody => &message.html_body,
                                Property::Attachments => &message.attachments,
                                _ => unreachable!(),
                            }
                            .iter();
                            email.append(
                                property.clone(),
                                list.map(|part_id| {
                                    message.parts.to_body_part(
                                        *part_id,
                                        &body_properties,
                                        &raw_message,
                                        &blob_id,
                                    )
                                })
                                .collect::<Vec<_>>(),
                            );
                        }
                    }
                    Property::BodyStructure => {
                        if let Some(message) = &message {
                            email.append(
                                Property::BodyStructure,
                                message.parts.to_body_part(
                                    0,
                                    &body_properties,
                                    &raw_message,
                                    &blob_id,
                                ),
                            );
                        }
                    }
                    Property::BodyValues => {
                        if let Some(message) = &message {
                            let mut body_values = Object::with_capacity(message.parts.len());
                            for (part_id, part) in message.parts.iter().enumerate() {
                                if ((message.html_body.contains(&part_id)
                                    && (fetch_all_body_values || fetch_html_body_values))
                                    || (message.text_body.contains(&part_id)
                                        && (fetch_all_body_values || fetch_text_body_values)))
                                    && part.is_text()
                                {
                                    let (is_truncated, value) =
                                        part.body.truncate(max_body_value_bytes);
                                    body_values.append(
                                        Property::_T(part_id.to_string()),
                                        Object::with_capacity(3)
                                            .with_property(
                                                Property::IsEncodingProblem,
                                                part.is_encoding_problem,
                                            )
                                            .with_property(Property::IsTruncated, is_truncated)
                                            .with_property(Property::Value, value),
                                    );
                                }
                            }
                            email.append(Property::BodyValues, body_values);
                        }
                    }

                    _ => {
                        return Err(MethodError::InvalidArguments(format!(
                            "Invalid property {property:?}"
                        )));
                    }
                }
            }
            response.list.push(email);
        }

        Ok(response)
    }
}
