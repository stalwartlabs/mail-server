/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    body::{ToBodyPart, truncate_html, truncate_plain},
    headers::IntoForm,
};
use crate::{
    blob::download::BlobDownload, changes::state::MessageCacheState, email::headers::HeaderToValue,
};
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::metadata::{ArchivedMetadataPartType, MessageMetadata},
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::email::GetArguments,
    types::{
        acl::Acl,
        blob::BlobId,
        collection::Collection,
        date::UTCDate,
        id::Id,
        property::{HeaderForm, Property},
        value::{Object, Value},
    },
};
use mail_parser::{ArchivedHeaderName, HeaderValue, core::rkyv::ArchivedGetHeader};
use std::{borrow::Cow, future::Future};
use store::BlobClass;
use trc::{AddContext, StoreEvent};
use utils::BlobHash;

pub trait EmailGet: Sync + Send {
    fn email_get(
        &self,
        request: GetRequest<GetArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;
}

impl EmailGet for Server {
    async fn email_get(
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
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let message_ids = if access_token.is_member(account_id) {
            cache.email_document_ids()
        } else {
            cache.shared_messages(access_token, Acl::ReadItems)
        };

        let ids = if let Some(ids) = ids {
            ids
        } else {
            cache
                .emails
                .items
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|item| Id::from_parts(item.thread_id, item.document_id))
                .collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
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

        for id in ids {
            // Obtain the email object
            if !message_ids.contains(id.document_id()) {
                response.not_found.push(id.into());
                continue;
            }
            let metadata_ = match self
                .get_archive_by_property(
                    account_id,
                    Collection::Email,
                    id.document_id(),
                    &Property::BodyStructure,
                )
                .await?
            {
                Some(metadata) => metadata,
                None => {
                    response.not_found.push(id.into());
                    continue;
                }
            };
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;

            // Obtain message data
            let data = match cache.email_by_id(&id.document_id()) {
                Some(data) => data,
                None => {
                    response.not_found.push(id.into());
                    continue;
                }
            };

            // Retrieve raw message if needed
            let blob_hash = BlobHash::from(&metadata.blob_hash);
            let raw_message: Cow<[u8]> = if needs_body {
                if let Some(raw_message) = self.get_blob(&blob_hash, 0..usize::MAX).await? {
                    raw_message.into()
                } else {
                    trc::event!(
                        Store(StoreEvent::NotFound),
                        AccountId = account_id,
                        DocumentId = id.document_id(),
                        Collection = Collection::Email,
                        BlobId = blob_hash.to_hex(),
                        Details = "Blob not found.",
                        CausedBy = trc::location!(),
                    );

                    response.not_found.push(id.into());
                    continue;
                }
            } else {
                metadata.raw_headers.as_slice().into()
            };
            let blob_id = BlobId {
                hash: blob_hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id: id.document_id(),
                },
                section: None,
            };

            // Prepare response
            let mut email = Object::with_capacity(properties.len());
            let contents = &metadata.contents[0];
            let root_part = &contents.parts[0];
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
                        let mut obj = Object::with_capacity(data.mailboxes.len());
                        for id in data.mailboxes.iter() {
                            debug_assert!(id.uid != 0);
                            obj.append(Property::_T(Id::from(id.mailbox_id).to_string()), true);
                        }

                        email.append(property.clone(), Value::Object(obj));
                    }
                    Property::Keywords => {
                        let mut obj = Object::with_capacity(2);
                        for keyword in cache.expand_keywords(data) {
                            obj.append(Property::_T(keyword.to_string()), true);
                        }
                        email.append(property.clone(), Value::Object(obj));
                    }
                    Property::Size => {
                        email.append(Property::Size, u32::from(metadata.size));
                    }
                    Property::ReceivedAt => {
                        email.append(
                            Property::ReceivedAt,
                            Value::Date(UTCDate::from_timestamp(
                                u64::from(metadata.received_at) as i64
                            )),
                        );
                    }
                    Property::Preview => {
                        if !metadata.preview.is_empty() {
                            email.append(Property::Preview, metadata.preview.to_string());
                        }
                    }
                    Property::HasAttachment => {
                        email.append(Property::HasAttachment, metadata.has_attachments);
                    }
                    Property::Subject => {
                        email.append(
                            Property::Subject,
                            root_part
                                .headers
                                .header_value(&ArchivedHeaderName::Subject)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Text))
                                .unwrap_or_default(),
                        );
                    }
                    Property::SentAt => {
                        email.append(
                            Property::SentAt,
                            root_part
                                .headers
                                .header_value(&ArchivedHeaderName::Date)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Date))
                                .unwrap_or_default(),
                        );
                    }
                    Property::MessageId | Property::InReplyTo | Property::References => {
                        email.append(
                            property.clone(),
                            root_part
                                .headers
                                .header_value(&match property {
                                    Property::MessageId => ArchivedHeaderName::MessageId,
                                    Property::InReplyTo => ArchivedHeaderName::InReplyTo,
                                    Property::References => ArchivedHeaderName::References,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::MessageIds)
                                })
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
                            root_part
                                .headers
                                .header_value(&match property {
                                    Property::Sender => ArchivedHeaderName::Sender,
                                    Property::From => ArchivedHeaderName::From,
                                    Property::To => ArchivedHeaderName::To,
                                    Property::Cc => ArchivedHeaderName::Cc,
                                    Property::Bcc => ArchivedHeaderName::Bcc,
                                    Property::ReplyTo => ArchivedHeaderName::ReplyTo,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::Addresses)
                                })
                                .unwrap_or_default(),
                        );
                    }
                    Property::Header(_) => {
                        email.append(
                            property.clone(),
                            root_part.headers.header_to_value(property, &raw_message),
                        );
                    }
                    Property::Headers => {
                        email.append(
                            Property::Headers,
                            root_part.headers.headers_to_value(&raw_message),
                        );
                    }
                    Property::TextBody | Property::HtmlBody | Property::Attachments => {
                        let list = match property {
                            Property::TextBody => &contents.text_body,
                            Property::HtmlBody => &contents.html_body,
                            Property::Attachments => &contents.attachments,
                            _ => unreachable!(),
                        }
                        .iter();
                        email.append(
                            property.clone(),
                            list.map(|part_id| {
                                contents.to_body_part(
                                    u16::from(part_id) as u32,
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
                            contents.to_body_part(0, &body_properties, &raw_message, &blob_id),
                        );
                    }
                    Property::BodyValues => {
                        let mut body_values = Object::with_capacity(contents.parts.len());
                        for (part_id, part) in contents.parts.iter().enumerate() {
                            if ((contents.is_html_part(part_id as u16)
                                && (fetch_all_body_values || fetch_html_body_values))
                                || (contents.is_text_part(part_id as u16)
                                    && (fetch_all_body_values || fetch_text_body_values)))
                                && matches!(
                                    part.body,
                                    ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html
                                )
                            {
                                let contents = part.decode_contents(&raw_message);

                                let (is_truncated, value) = match &part.body {
                                    ArchivedMetadataPartType::Text => {
                                        truncate_plain(contents.as_str(), max_body_value_bytes)
                                    }
                                    ArchivedMetadataPartType::Html => {
                                        truncate_html(contents.as_str(), max_body_value_bytes)
                                    }
                                    _ => unreachable!(),
                                };

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
                        return Err(trc::JmapEvent::InvalidArguments
                            .into_err()
                            .details(format!("Invalid property {property:?}")));
                    }
                }
            }
            response.list.push(email);
        }

        Ok(response)
    }
}
