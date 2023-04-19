use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse},
    object::{email::GetArguments, Object},
    types::{
        blob::BlobId, collection::Collection, id::Id, keyword::Keyword, property::Property,
        value::Value,
    },
};
use mail_parser::Message;

use crate::{email::headers::HeaderToValue, JMAP};

use super::body::{ToBodyPart, TruncateBody};

impl JMAP {
    pub async fn email_get(
        &self,
        request: GetRequest<GetArguments>,
    ) -> Result<GetResponse, MethodError> {
        let properties = request.properties.map(|v| v.unwrap()).unwrap_or_else(|| {
            vec![
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
            ]
        });
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

        let ids = if let Some(ids) = request.ids.map(|v| v.unwrap()) {
            ids
        } else {
            let implement = "";
            todo!()
        };
        let account_id = request.account_id.document_id();
        let mut response = GetResponse {
            account_id: Some(request.account_id),
            state: self.get_state(account_id, Collection::Email).await?,
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

        for id in ids {
            // Obtain the email object
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
                        email.append(
                            property.clone(),
                            self.get_property::<Vec<u32>>(
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
                            .unwrap_or(Value::Null),
                        );
                    }
                    Property::Keywords => {
                        email.append(
                            property.clone(),
                            self.get_property::<Vec<Keyword>>(
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
                            .unwrap_or(Value::Null),
                        );
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
                                if (message.html_body.contains(&part_id)
                                    && (fetch_all_body_values || fetch_html_body_values))
                                    || (message.text_body.contains(&part_id)
                                        && (fetch_all_body_values || fetch_text_body_values))
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
