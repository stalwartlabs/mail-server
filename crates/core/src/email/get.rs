use mail_parser::Message;
use protocol::{
    error::method::MethodError,
    method::get::GetResponse,
    object::{email::GetArguments, Object},
    types::{collection::Collection, id::Id, property::Property, value::Value},
};
use store::ValueKey;

use crate::{email::headers::HeaderToValue, JMAP};

impl JMAP {
    pub async fn email_get(
        &self,
        account_id: u32,
        ids: Vec<Id>,
        properties: Option<Vec<Property>>,
        arguments: GetArguments,
    ) -> Result<GetResponse, MethodError> {
        let properties = properties.unwrap_or_else(|| {
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
        let body_properties = arguments.body_properties.unwrap_or_else(|| {
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
        let mut response = GetResponse {
            account_id: Some(account_id.into()),
            state: self
                .store
                .get_last_change_id(account_id, Collection::Email)
                .await?
                .into(),
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
            let mut values = if let Some(value) = self
                .store
                .get_value::<Object<Value>>(ValueKey::new(
                    account_id,
                    Collection::Email,
                    id.document_id(),
                    Property::BodyStructure,
                ))
                .await?
            {
                value
            } else {
                response.not_found.push(id);
                continue;
            };

            // Retrieve raw message if needed
            let blob_id = values.get(&Property::BlobId).as_blob()?;
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

                if let Some(raw_message) = self.store.get_blob(&blob_id.hash, 0..offset).await? {
                    raw_message
                } else {
                    let log = "true";
                    response.not_found.push(id);
                    continue;
                }
            } else {
                vec![]
            };
            let message = if !raw_message.is_empty() {
                let message = Message::parse(&raw_message);
                if message.is_none() {
                    let log = "true";
                }
                message
            } else {
                None
            };
            let blob_hash = blob_id.hash;

            // Prepare response
            let mut email = Object::with_capacity(properties.len());
            for property in &properties {
                match property {
                    Property::Id => {
                        email.append(Property::Id, *id);
                    }
                    Property::ThreadId => {
                        email.append(Property::ThreadId, id.prefix_id());
                    }
                    Property::BlobId => {
                        email.append(Property::BlobId, blob_hash);
                    }
                    Property::MailboxIds | Property::Keywords => {
                        email.append(
                            property.clone(),
                            self.store
                                .get_value::<Value>(ValueKey::new(
                                    account_id,
                                    Collection::Email,
                                    id.document_id(),
                                    property.clone(),
                                ))
                                .await?
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
