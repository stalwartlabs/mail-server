/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::method::MethodError,
    method::get::{GetRequest, GetResponse},
    object::{email::GetArguments, Object},
    types::{
        acl::Acl,
        blob::BlobId,
        collection::Collection,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::{HeaderForm, Property},
        value::Value,
    },
};
use mail_parser::HeaderName;
use store::{write::Bincode, BlobClass};
use trc::AddContext;

use crate::{auth::AccessToken, email::headers::HeaderToValue, mailbox::UidMailbox, JMAP};

use super::{
    body::{ToBodyPart, TruncateBody},
    headers::IntoForm,
    metadata::{MessageMetadata, MetadataPartType},
};

impl JMAP {
    pub async fn email_get(
        &self,
        mut request: GetRequest<GetArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
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
                .take(self.core.jmap.get_max_objects)
                .collect::<Vec<_>>();
            self.get_cached_thread_ids(account_id, document_ids.iter().copied())
                .await
                .caused_by(trc::location!())?
                .into_iter()
                .filter_map(|(document_id, thread_id)| {
                    Id::from_parts(thread_id, document_id).into()
                })
                .collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self.get_state(account_id, Collection::Email).await?.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        // Check if we need to fetch the raw headers or body
        let mut needs_body = false;
        for property in &properties {
            if matches!(
                property,
                Property::BodyValues
                    | Property::TextBody
                    | Property::HtmlBody
                    | Property::Attachments
                    | Property::BodyStructure
            ) {
                needs_body = true;
                break;
            }
        }

        'outer: for id in ids {
            // Obtain the email object
            if !message_ids.contains(id.document_id()) {
                response.not_found.push(id.into());
                continue;
            }
            let mut metadata = match self
                .get_property::<Bincode<MessageMetadata>>(
                    account_id,
                    Collection::Email,
                    id.document_id(),
                    &Property::BodyStructure,
                )
                .await?
            {
                Some(metadata) => metadata.inner,
                None => {
                    response.not_found.push(id.into());
                    continue;
                }
            };

            // Retrieve raw message if needed
            let raw_message = if needs_body {
                if let Some(raw_message) = self.get_blob(&metadata.blob_hash, 0..usize::MAX).await?
                {
                    raw_message
                } else {
                    tracing::warn!(event = "not-found",
                        account_id = account_id,
                        collection = ?Collection::Email,
                        document_id = id.document_id(),
                        blob_id = ?metadata.blob_hash,
                        "Blob not found");
                    response.not_found.push(id.into());
                    continue;
                }
            } else {
                metadata.raw_headers
            };
            let blob_id = BlobId {
                hash: metadata.blob_hash.clone(),
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id: id.document_id(),
                },
                section: None,
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
                            .get_property::<Vec<UidMailbox>>(
                                account_id,
                                Collection::Email,
                                id.document_id(),
                                &Property::MailboxIds,
                            )
                            .await?
                            .map(|ids| {
                                let mut obj = Object::with_capacity(ids.len());
                                for id in ids {
                                    debug_assert!(id.uid != 0);
                                    obj.append(
                                        Property::_T(Id::from(id.mailbox_id).to_string()),
                                        true,
                                    );
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
                            response.not_found.push(id.into());
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
                            response.not_found.push(id.into());
                            continue 'outer;
                        }
                    }
                    Property::Size => {
                        email.append(Property::Size, metadata.size);
                    }
                    Property::ReceivedAt => {
                        email.append(
                            Property::ReceivedAt,
                            Value::Date(UTCDate::from_timestamp(metadata.received_at as i64)),
                        );
                    }
                    Property::Preview => {
                        if !metadata.preview.is_empty() {
                            email.append(Property::Preview, std::mem::take(&mut metadata.preview));
                        }
                    }
                    Property::HasAttachment => {
                        email.append(Property::HasAttachment, metadata.has_attachments);
                    }
                    Property::Subject => {
                        email.append(
                            Property::Subject,
                            metadata.contents.parts[0]
                                .remove_header(&HeaderName::Subject)
                                .map(|value| value.into_form(&HeaderForm::Text))
                                .unwrap_or_default(),
                        );
                    }
                    Property::SentAt => {
                        email.append(
                            Property::SentAt,
                            metadata.contents.parts[0]
                                .remove_header(&HeaderName::Date)
                                .map(|value| value.into_form(&HeaderForm::Date))
                                .unwrap_or_default(),
                        );
                    }
                    Property::MessageId | Property::InReplyTo | Property::References => {
                        email.append(
                            property.clone(),
                            metadata.contents.parts[0]
                                .remove_header(&match property {
                                    Property::MessageId => HeaderName::MessageId,
                                    Property::InReplyTo => HeaderName::InReplyTo,
                                    Property::References => HeaderName::References,
                                    _ => unreachable!(),
                                })
                                .map(|value| value.into_form(&HeaderForm::MessageIds))
                                .unwrap_or_default(),
                        );
                    }

                    Property::Sender
                    | Property::From
                    | Property::To
                    | Property::Cc
                    | Property::Bcc
                    | Property::ReplyTo => {
                        email.append(
                            property.clone(),
                            metadata.contents.parts[0]
                                .remove_header(&match property {
                                    Property::Sender => HeaderName::Sender,
                                    Property::From => HeaderName::From,
                                    Property::To => HeaderName::To,
                                    Property::Cc => HeaderName::Cc,
                                    Property::Bcc => HeaderName::Bcc,
                                    Property::ReplyTo => HeaderName::ReplyTo,
                                    _ => unreachable!(),
                                })
                                .map(|value| value.into_form(&HeaderForm::Addresses))
                                .unwrap_or_default(),
                        );
                    }
                    Property::Header(_) => {
                        email.append(
                            property.clone(),
                            metadata.contents.parts[0]
                                .headers
                                .header_to_value(property, &raw_message),
                        );
                    }
                    Property::Headers => {
                        email.append(
                            Property::Headers,
                            metadata.contents.parts[0]
                                .headers
                                .headers_to_value(&raw_message),
                        );
                    }
                    Property::TextBody | Property::HtmlBody | Property::Attachments => {
                        let list = match property {
                            Property::TextBody => &metadata.contents.text_body,
                            Property::HtmlBody => &metadata.contents.html_body,
                            Property::Attachments => &metadata.contents.attachments,
                            _ => unreachable!(),
                        }
                        .iter();
                        email.append(
                            property.clone(),
                            list.map(|part_id| {
                                metadata.contents.to_body_part(
                                    *part_id,
                                    &body_properties,
                                    &raw_message,
                                    &blob_id,
                                )
                            })
                            .collect::<Vec<_>>(),
                        );
                    }
                    Property::BodyStructure => {
                        email.append(
                            Property::BodyStructure,
                            metadata.contents.to_body_part(
                                0,
                                &body_properties,
                                &raw_message,
                                &blob_id,
                            ),
                        );
                    }
                    Property::BodyValues => {
                        let mut body_values = Object::with_capacity(metadata.contents.parts.len());
                        for (part_id, part) in metadata.contents.parts.iter().enumerate() {
                            if ((metadata.contents.html_body.contains(&part_id)
                                && (fetch_all_body_values || fetch_html_body_values))
                                || (metadata.contents.text_body.contains(&part_id)
                                    && (fetch_all_body_values || fetch_text_body_values)))
                                && matches!(
                                    part.body,
                                    MetadataPartType::Text | MetadataPartType::Html
                                )
                            {
                                let (is_truncated, value) = part
                                    .decode_contents(&raw_message)
                                    .truncate(max_body_value_bytes);
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

                    _ => {
                        return Err(MethodError::InvalidArguments(format!(
                            "Invalid property {property:?}"
                        ))
                        .into());
                    }
                }
            }
            response.list.push(email);
        }

        Ok(response)
    }
}
