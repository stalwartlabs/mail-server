/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::{borrow::Cow, collections::HashMap, slice::IterMut};

use jmap_proto::{
    error::{
        method::MethodError,
        set::{SetError, SetErrorType},
    },
    method::set::{RequestArguments, SetRequest, SetResponse},
    response::references::EvalObjectReferences,
    types::{
        acl::Acl,
        collection::Collection,
        keyword::Keyword,
        property::Property,
        state::{State, StateChange},
        type_state::DataType,
        value::{MaybePatchValue, SetValue, Value},
    },
};
use mail_builder::{
    headers::{
        address::Address, content_type::ContentType, date::Date, message_id::MessageId, raw::Raw,
        text::Text, HeaderType,
    },
    mime::{BodyPart, MimePart},
    MessageBuilder,
};
use mail_parser::MessageParser;
use store::{
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{
        assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, DeserializeFrom, SerializeInto,
        ToBitmaps, ValueClass, F_BITMAP, F_CLEAR, F_VALUE,
    },
    Serialize,
};

use crate::{auth::AccessToken, mailbox::UidMailbox, IngestError, JMAP};

use super::{
    headers::{BuildHeader, ValueToHeader},
    ingest::{IngestEmail, IngestSource},
};

impl JMAP {
    pub async fn email_set(
        &self,
        mut request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> Result<SetResponse, MethodError> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let mut response = self
            .prepare_set_response(&request, Collection::Email)
            .await?;

        // Obtain mailboxIds
        let mailbox_ids = self.mailbox_get_or_create(account_id).await?;
        let (can_add_mailbox_ids, can_delete_mailbox_ids, can_modify_message_ids) = if access_token
            .is_shared(account_id)
        {
            (
                self.shared_documents(access_token, account_id, Collection::Mailbox, Acl::AddItems)
                    .await?
                    .into(),
                self.shared_documents(
                    access_token,
                    account_id,
                    Collection::Mailbox,
                    Acl::RemoveItems,
                )
                .await?
                .into(),
                self.shared_messages(access_token, account_id, Acl::ModifyItems)
                    .await?
                    .into(),
            )
        } else {
            (None, None, None)
        };

        let will_destroy = request.unwrap_destroy();

        // Obtain quota
        let account_quota = self.get_quota(access_token, account_id).await?;

        // Process creates
        'create: for (id, mut object) in request.unwrap_create() {
            let has_body_structure = object
                .properties
                .keys()
                .any(|key| matches!(key, Property::BodyStructure));
            let mut builder = MessageBuilder::new();
            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            // Parse body values
            let body_values = object
                .properties
                .remove(&Property::BodyValues)
                .and_then(|obj| {
                    if let SetValue::Value(Value::Object(obj)) = obj {
                        let mut values = HashMap::with_capacity(obj.properties.len());
                        for (key, value) in obj.properties {
                            if let (Property::_T(id), Value::Object(mut bv)) = (key, value) {
                                values.insert(
                                    id,
                                    bv.properties
                                        .remove(&Property::Value)?
                                        .try_unwrap_string()?,
                                );
                            } else {
                                return None;
                            }
                        }
                        Some(values)
                    } else {
                        None
                    }
                });
            let mut size_attachments = 0;

            // Parse properties
            for (property, value) in object.properties {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };
                match (property, value) {
                    (Property::MailboxIds, MaybePatchValue::Value(Value::List(ids))) => {
                        mailboxes = ids
                            .into_iter()
                            .filter_map(|id| id.try_unwrap_id()?.document_id().into())
                            .collect();
                    }

                    (Property::MailboxIds, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(document_id) = patch.next().unwrap().try_unwrap_id() {
                            let document_id = document_id.document_id();
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !mailboxes.contains(&document_id) {
                                    mailboxes.push(document_id);
                                }
                            } else {
                                mailboxes.retain(|id| id != &document_id);
                            }
                        }
                    }

                    (Property::Keywords, MaybePatchValue::Value(Value::List(keywords_))) => {
                        keywords = keywords_
                            .into_iter()
                            .filter_map(|keyword| keyword.try_unwrap_keyword())
                            .collect();
                    }

                    (Property::Keywords, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(keyword) = patch.next().unwrap().try_unwrap_keyword() {
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                if !keywords.contains(&keyword) {
                                    keywords.push(keyword);
                                }
                            } else {
                                keywords.retain(|k| k != &keyword);
                            }
                        }
                    }

                    (
                        header @ (Property::MessageId | Property::InReplyTo | Property::References),
                        MaybePatchValue::Value(Value::List(values)),
                    ) => {
                        builder = builder.header(
                            header.as_rfc_header(),
                            MessageId {
                                id: values
                                    .into_iter()
                                    .filter_map(|value| value.try_unwrap_string())
                                    .map(|value| value.into())
                                    .collect(),
                            },
                        );
                    }

                    (
                        header @ (Property::Sender
                        | Property::From
                        | Property::To
                        | Property::Cc
                        | Property::Bcc
                        | Property::ReplyTo),
                        MaybePatchValue::Value(value),
                    ) => {
                        if let Some(addresses) = value.try_into_address_list() {
                            builder =
                                builder.header(header.as_rfc_header(), Address::List(addresses));
                        } else {
                            response.invalid_property_create(id, header);
                            continue 'create;
                        }
                    }
                    (Property::Subject, MaybePatchValue::Value(Value::Text(value))) => {
                        builder = builder.subject(value);
                    }

                    (Property::ReceivedAt, MaybePatchValue::Value(Value::Date(value))) => {
                        received_at = (value.timestamp() as u64).into();
                    }

                    (Property::SentAt, MaybePatchValue::Value(Value::Date(value))) => {
                        builder = builder.date(Date::new(value.timestamp()));
                    }

                    (
                        property @ (Property::TextBody
                        | Property::HtmlBody
                        | Property::Attachments
                        | Property::BodyStructure),
                        MaybePatchValue::Value(value),
                    ) => {
                        // Validate request
                        let (values, expected_content_type) = match property {
                            Property::BodyStructure => (vec![value], None),
                            Property::TextBody | Property::HtmlBody if !has_body_structure => {
                                let values = value.try_unwrap_list().unwrap_or_default();
                                if values.len() <= 1 {
                                    (
                                        values,
                                        Some(match property {
                                            Property::TextBody => "text/plain",
                                            Property::HtmlBody => "text/html",
                                            _ => unreachable!(),
                                        }),
                                    )
                                } else {
                                    response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property(property)
                                            .with_description("Only one part is allowed."),
                                    );
                                    continue 'create;
                                }
                            }
                            Property::Attachments if !has_body_structure => {
                                (value.try_unwrap_list().unwrap_or_default(), None)
                            }
                            _ => {
                                response.not_created.append(
                                    id,
                                    SetError::invalid_properties()
                                        .with_properties([property, Property::BodyStructure])
                                        .with_description(
                                            "Cannot set both properties on a same request.",
                                        ),
                                );
                                continue 'create;
                            }
                        };

                        // Iterate parts
                        let mut values_stack = Vec::new();
                        let mut values = values.into_iter();
                        let mut parts = Vec::new();
                        loop {
                            while let Some(value) = values.next() {
                                let mut blob_id = None;
                                let mut part_id = None;
                                let mut content_type = None;
                                let mut content_disposition = None;
                                let mut name = None;
                                let mut charset = None;
                                let mut subparts = None;
                                let mut has_size = false;
                                let mut headers: Vec<(Cow<str>, HeaderType)> = Vec::new();

                                if let Some(obj) = value.try_unwrap_object() {
                                    for (body_property, value) in obj.properties {
                                        match (body_property, value) {
                                            (Property::Type, Value::Text(value)) => {
                                                content_type = value.into();
                                            }
                                            (Property::PartId, Value::Text(value)) => {
                                                part_id = value.into();
                                            }
                                            (Property::BlobId, Value::BlobId(value)) => {
                                                blob_id = value.into();
                                            }
                                            (Property::Disposition, Value::Text(value)) => {
                                                content_disposition = value.into();
                                            }
                                            (Property::Name, Value::Text(value)) => {
                                                name = value.into();
                                            }
                                            (Property::Charset, Value::Text(value)) => {
                                                charset = value.into();
                                            }
                                            (Property::Language, Value::List(values)) => {
                                                headers.push((
                                                    "Content-Language".into(),
                                                    Text::new(
                                                        values
                                                            .into_iter()
                                                            .filter_map(|v| v.try_unwrap_string())
                                                            .fold(
                                                                String::with_capacity(64),
                                                                |mut h, v| {
                                                                    if !h.is_empty() {
                                                                        h.push_str(", ");
                                                                    }
                                                                    h.push_str(&v);
                                                                    h
                                                                },
                                                            ),
                                                    )
                                                    .into(),
                                                ));
                                            }
                                            (Property::Cid, Value::Text(value)) => {
                                                headers.push((
                                                    "Content-ID".into(),
                                                    MessageId::new(value).into(),
                                                ));
                                            }
                                            (Property::Location, Value::Text(value)) => {
                                                headers.push((
                                                    "Content-Location".into(),
                                                    Text::new(value).into(),
                                                ));
                                            }
                                            (Property::Header(header), Value::Text(value))
                                                if !header.header.eq_ignore_ascii_case(
                                                    "content-transfer-encoding",
                                                ) =>
                                            {
                                                headers.push((
                                                    header.header.into(),
                                                    Raw::from(value).into(),
                                                ));
                                            }
                                            (Property::Header(header), Value::List(values))
                                                if !header.header.eq_ignore_ascii_case(
                                                    "content-transfer-encoding",
                                                ) =>
                                            {
                                                for value in values {
                                                    if let Some(value) = value.try_unwrap_string() {
                                                        headers.push((
                                                            header.header.clone().into(),
                                                            Raw::from(value).into(),
                                                        ));
                                                    }
                                                }
                                            }
                                            (Property::Headers, _) => {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((
                                                            property,
                                                            Property::Headers,
                                                        ))
                                                        .with_description(
                                                            "Headers have to be set individually.",
                                                        ),
                                                );
                                                continue 'create;
                                            }
                                            (Property::Size, _) => {
                                                has_size = true;
                                            }
                                            (Property::SubParts, Value::List(values)) => {
                                                subparts = values.into();
                                            }
                                            (body_property, value) if value != Value::Null => {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((property, body_property))
                                                        .with_description("Cannot set property."),
                                                );
                                                continue 'create;
                                            }
                                            _ => {}
                                        }
                                    }
                                }

                                // Validate content-type
                                let content_type =
                                    content_type.unwrap_or_else(|| "text/plain".to_string());
                                let is_multipart = content_type.starts_with("multipart/");
                                if is_multipart {
                                    if !matches!(property, Property::BodyStructure) {
                                        response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property((property, Property::Type))
                                                .with_description("Multiparts can only be set with bodyStructure."),
                                        );
                                        continue 'create;
                                    }
                                } else if expected_content_type
                                    .as_ref()
                                    .map_or(false, |v| v != &content_type)
                                {
                                    response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property((property, Property::Type))
                                            .with_description(format!(
                                                "Expected one body part of type \"{}\"",
                                                expected_content_type.unwrap()
                                            )),
                                    );
                                    continue 'create;
                                }

                                // Validate partId/blobId
                                match (blob_id.is_some(), part_id.is_some()) {
                                    (true, true) if !is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_properties([(property.clone(), Property::BlobId), (property, Property::PartId)])
                                            .with_description(
                                                "Cannot specify both \"partId\" and \"blobId\".",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    (false, false) if !is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_description("Expected a \"partId\" or \"blobId\" field in body part."),
                                    );
                                        continue 'create;
                                    }
                                    (false, true) if !is_multipart && has_size => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property((property, Property::Size))
                                            .with_description(
                                                "Cannot specify \"size\" when providing a \"partId\".",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    (true, _) | (_, true) if is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_properties([(property.clone(), Property::BlobId), (property, Property::PartId)])
                                            .with_description(
                                                "Cannot specify \"partId\" or \"blobId\" in multipart body parts.",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    _ => (),
                                }

                                // Set Content-Type and Content-Disposition
                                let mut content_type = ContentType::new(content_type);
                                if !is_multipart {
                                    if let Some(charset) = charset {
                                        if part_id.is_none() {
                                            content_type
                                                .attributes
                                                .push(("charset".into(), charset.into()));
                                        } else {
                                            response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property((property, Property::Charset))
                                                .with_description(
                                                    "Cannot specify a character set when providing a \"partId\".",
                                                ),
                                        );
                                            continue 'create;
                                        }
                                    } else if part_id.is_some() {
                                        content_type
                                            .attributes
                                            .push(("charset".into(), "utf-8".into()));
                                    }
                                    match (content_disposition, name) {
                                        (Some(disposition), Some(filename)) => {
                                            headers.push((
                                                "Content-Disposition".into(),
                                                ContentType::new(disposition)
                                                    .attribute("filename", filename)
                                                    .into(),
                                            ));
                                        }
                                        (Some(disposition), None) => {
                                            headers.push((
                                                "Content-Disposition".into(),
                                                ContentType::new(disposition).into(),
                                            ));
                                        }
                                        (None, Some(filename)) => {
                                            content_type
                                                .attributes
                                                .push(("name".into(), filename.into()));
                                        }
                                        (None, None) => (),
                                    };
                                }
                                headers.push(("Content-Type".into(), content_type.into()));

                                // In test, sort headers to avoid randomness
                                #[cfg(feature = "test_mode")]
                                {
                                    headers.sort_unstable_by(|a, b| match a.0.cmp(&b.0) {
                                        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
                                        ord => ord,
                                    });
                                }
                                // Retrieve contents
                                parts.push(MimePart {
                                    headers,
                                    contents: if !is_multipart {
                                        if let Some(blob_id) = blob_id {
                                            match self.blob_download(&blob_id, access_token).await? {
                                                Some(contents) => {
                                                    BodyPart::Binary(contents.into())
                                                }
                                                None => {
                                                    response.not_created.append(
                                                    id,
                                                    SetError::new(SetErrorType::BlobNotFound).with_description(
                                                        format!("blobId {blob_id} does not exist on this server.")
                                                    ),
                                                );
                                                    continue 'create;
                                                }
                                            }
                                        } else if let Some(part_id) = part_id {
                                            if let Some(contents) =
                                                body_values.as_ref().and_then(|bv| bv.get(&part_id))
                                            {
                                                BodyPart::Text(contents.as_str().into())
                                            } else {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((property, Property::PartId))
                                                        .with_description(format!(
                                                        "Missing body value for partId {part_id:?}"
                                                    )),
                                                );
                                                continue 'create;
                                            }
                                        } else {
                                            unreachable!()
                                        }
                                    } else {
                                        BodyPart::Multipart(vec![])
                                    },
                                });

                                // Check attachment sizes
                                if !is_multipart {
                                    size_attachments += parts.last().unwrap().size();
                                    if self.core.jmap.mail_attachments_max_size > 0
                                        && size_attachments
                                            > self.core.jmap.mail_attachments_max_size
                                    {
                                        response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property(property)
                                                .with_description(format!(
                                                    "Message exceeds maximum size of {} bytes.",
                                                    self.core.jmap.mail_attachments_max_size
                                                )),
                                        );
                                        continue 'create;
                                    }
                                } else if let Some(subparts) = subparts {
                                    values_stack.push((values, parts));
                                    parts = Vec::with_capacity(subparts.len());
                                    values = subparts.into_iter();
                                    continue;
                                }
                            }

                            if let Some((prev_values, mut prev_parts)) = values_stack.pop() {
                                values = prev_values;
                                prev_parts.last_mut().unwrap().contents =
                                    BodyPart::Multipart(parts);
                                parts = prev_parts;
                            } else {
                                break;
                            }
                        }

                        match property {
                            Property::TextBody => {
                                builder.text_body = parts.pop();
                            }
                            Property::HtmlBody => {
                                builder.html_body = parts.pop();
                            }
                            Property::Attachments => {
                                builder.attachments = parts.into();
                            }
                            _ => {
                                builder.body = parts.pop();
                            }
                        }
                    }

                    (Property::Header(header), MaybePatchValue::Value(value)) => {
                        match builder.build_header(header, value) {
                            Ok(builder_) => {
                                builder = builder_;
                            }
                            Err(header) => {
                                response.invalid_property_create(id, Property::Header(header));
                                continue 'create;
                            }
                        }
                    }

                    (_, MaybePatchValue::Value(Value::Null)) => (),

                    (property, _) => {
                        response.invalid_property_create(id, property);
                        continue 'create;
                    }
                }
            }

            // Make sure message belongs to at least one mailbox
            if mailboxes.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message has to belong to at least one mailbox."),
                );
                continue 'create;
            }

            // Verify that the mailboxIds are valid
            for mailbox_id in &mailboxes {
                if !mailbox_ids.contains(*mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description(format!("mailboxId {mailbox_id} does not exist.")),
                    );
                    continue 'create;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'create;
                }
            }

            // Make sure the message is not empty
            if builder.headers.is_empty()
                && builder.body.is_none()
                && builder.html_body.is_none()
                && builder.text_body.is_none()
                && builder.attachments.is_none()
            {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("Message has to have at least one header or body part."),
                );
                continue 'create;
            }

            // In test, sort headers to avoid randomness
            #[cfg(feature = "test_mode")]
            {
                builder
                    .headers
                    .sort_unstable_by(|a, b| match a.0.cmp(&b.0) {
                        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
                        ord => ord,
                    });
            }

            // Build message
            let mut raw_message = Vec::with_capacity((4 * size_attachments / 3) + 1024);
            builder.write_to(&mut raw_message).unwrap_or_default();

            // Ingest message
            match self
                .email_ingest(IngestEmail {
                    raw_message: &raw_message,
                    message: MessageParser::new().parse(&raw_message),
                    account_id,
                    account_quota,
                    mailbox_ids: mailboxes,
                    keywords,
                    received_at,
                    source: IngestSource::Jmap,
                    encrypt: self.core.jmap.encrypt && self.core.jmap.encrypt_append,
                })
                .await
            {
                Ok(message) => {
                    response.created.insert(id, message.into());
                }
                Err(IngestError::OverQuota) => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::OverQuota)
                            .with_description("You have exceeded your disk quota."),
                    );
                }
                Err(_) => return Err(MethodError::ServerPartialFail),
            }
        }

        // Process updates
        let mut changes = ChangeLogBuilder::new();
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain current keywords and mailboxes
            let document_id = id.document_id();
            let (mut mailboxes, mut keywords) = if let (Some(mailboxes), Some(keywords)) = (
                self.get_property::<HashedValue<Vec<UidMailbox>>>(
                    account_id,
                    Collection::Email,
                    document_id,
                    Property::MailboxIds,
                )
                .await?,
                self.get_property::<HashedValue<Vec<Keyword>>>(
                    account_id,
                    Collection::Email,
                    document_id,
                    Property::Keywords,
                )
                .await?,
            ) {
                (TagManager::new(mailboxes), TagManager::new(keywords))
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email);

            for (property, value) in object.properties {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };
                match (property, value) {
                    (Property::MailboxIds, MaybePatchValue::Value(Value::List(ids))) => {
                        mailboxes.set(
                            ids.into_iter()
                                .filter_map(|id| {
                                    UidMailbox::new_unassigned(id.try_unwrap_id()?.document_id())
                                        .into()
                                })
                                .collect(),
                        );
                    }
                    (Property::MailboxIds, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(id) = patch.next().unwrap().try_unwrap_id() {
                            mailboxes.update(
                                UidMailbox::new_unassigned(id.document_id()),
                                patch.next().unwrap().try_unwrap_bool().unwrap_or_default(),
                            );
                        }
                    }
                    (Property::Keywords, MaybePatchValue::Value(Value::List(keywords_))) => {
                        keywords.set(
                            keywords_
                                .into_iter()
                                .filter_map(|keyword| keyword.try_unwrap_keyword())
                                .collect(),
                        );
                    }
                    (Property::Keywords, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(keyword) = patch.next().unwrap().try_unwrap_keyword() {
                            keywords.update(
                                keyword,
                                patch.next().unwrap().try_unwrap_bool().unwrap_or_default(),
                            );
                        }
                    }
                    (property, _) => {
                        response.invalid_property_update(id, property);
                        continue 'update;
                    }
                }
            }

            if !mailboxes.has_changes() && !keywords.has_changes() {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("No changes found in request.".to_string()),
                );
                continue 'update;
            }

            // Log change
            batch.update_document(document_id);
            let mut changed_mailboxes = AHashSet::new();
            changes.log_update(Collection::Email, id);

            // Process keywords
            if keywords.has_changes() {
                // Verify permissions on shared accounts
                if matches!(&can_modify_message_ids, Some(ids) if !ids.contains(document_id)) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify keywords."),
                    );
                    continue 'update;
                }

                // Set all current mailboxes as changed if the Seen tag changed
                if keywords
                    .changed_tags()
                    .any(|keyword| keyword == &Keyword::Seen)
                {
                    for mailbox_id in mailboxes.current() {
                        changed_mailboxes.insert(mailbox_id.mailbox_id);
                    }
                }

                // Update keywords property
                keywords.update_batch(&mut batch, Property::Keywords);

                // Update last change id
                if changes.change_id == u64::MAX {
                    changes.change_id = self.assign_change_id(account_id).await?;
                }
                batch.value(Property::Cid, changes.change_id, F_VALUE);
            }

            // Process mailboxes
            if mailboxes.has_changes() {
                // Make sure the message is at least in one mailbox
                if !mailboxes.has_tags() {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description("Message has to belong to at least one mailbox."),
                    );
                    continue 'update;
                }

                // Make sure all new mailboxIds are valid
                for mailbox_id in mailboxes.added() {
                    if mailbox_ids.contains(mailbox_id.mailbox_id) {
                        // Verify permissions on shared accounts
                        if !matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(mailbox_id.mailbox_id))
                        {
                            changed_mailboxes.insert(mailbox_id.mailbox_id);
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::forbidden().with_description(format!(
                                    "You are not allowed to add messages to mailbox {}.",
                                    mailbox_id.mailbox_id
                                )),
                            );
                            continue 'update;
                        }
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(Property::MailboxIds)
                                .with_description(format!(
                                    "mailboxId {} does not exist.",
                                    mailbox_id.mailbox_id
                                )),
                        );
                        continue 'update;
                    }
                }

                // Add all removed mailboxes to change list
                for mailbox_id in mailboxes.removed() {
                    // Verify permissions on shared accounts
                    if !matches!(&can_delete_mailbox_ids, Some(ids) if !ids.contains(mailbox_id.mailbox_id))
                    {
                        changed_mailboxes.insert(mailbox_id.mailbox_id);
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to delete messages from mailbox {}.",
                                mailbox_id.mailbox_id
                            )),
                        );
                        continue 'update;
                    }
                }

                // Obtain IMAP UIDs for added mailboxes
                for uid_mailbox in mailboxes.inner_tags_mut() {
                    if uid_mailbox.uid == 0 {
                        uid_mailbox.uid = self
                            .assign_imap_uid(account_id, uid_mailbox.mailbox_id)
                            .await
                            .map_err(|err| {
                                tracing::error!(
                                    event = "error",
                                    context = "email_copy",
                                    error = ?err,
                                    "Failed to assign IMAP UID.");
                                MethodError::ServerPartialFail
                            })?;
                    }
                }

                // Update mailboxIds property
                mailboxes.update_batch(&mut batch, Property::MailboxIds);
            }

            // Log mailbox changes
            for mailbox_id in changed_mailboxes {
                changes.log_child_update(Collection::Mailbox, mailbox_id);
            }

            // Write changes
            if !batch.is_empty() {
                match self.core.storage.data.write(batch.build()).await {
                    Ok(_) => {
                        // Add to updated list
                        response.updated.append(id, None);
                    }
                    Err(store::Error::AssertValueFailed) => {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this message, please try again.",
                            ),
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            event = "error",
                            context = "email_set",
                            error = ?err,
                            "Failed to write message changes to database.");
                        return Err(MethodError::ServerPartialFail);
                    }
                }
            }
        }

        // Process deletions
        if !will_destroy.is_empty() {
            let email_ids = self
                .get_document_ids(account_id, Collection::Email)
                .await?
                .unwrap_or_default();
            let can_destroy_message_ids = if access_token.is_shared(account_id) {
                self.shared_messages(access_token, account_id, Acl::RemoveItems)
                    .await?
                    .into()
            } else {
                None
            };
            let mut destroy_ids = RoaringBitmap::new();
            for destroy_id in will_destroy {
                let document_id = destroy_id.document_id();

                if email_ids.contains(document_id) {
                    if !matches!(&can_destroy_message_ids, Some(ids) if !ids.contains(document_id))
                    {
                        destroy_ids.insert(document_id);
                        response.destroyed.push(destroy_id);
                    } else {
                        response.not_destroyed.append(
                            destroy_id,
                            SetError::forbidden()
                                .with_description("You are not allowed to delete this message."),
                        );
                    }
                } else {
                    response
                        .not_destroyed
                        .append(destroy_id, SetError::not_found());
                }
            }

            if !destroy_ids.is_empty() {
                // Batch delete (tombstone) messages
                let (change, not_destroyed) =
                    self.emails_tombstone(account_id, destroy_ids).await?;

                // Merge changes
                changes.merge(change);

                // Mark messages that were not found as not destroyed (this should not occur in practice)
                if !not_destroyed.is_empty() {
                    let mut destroyed = Vec::with_capacity(response.destroyed.len());

                    for destroy_id in response.destroyed {
                        if not_destroyed.contains(destroy_id.document_id()) {
                            response
                                .not_destroyed
                                .append(destroy_id, SetError::not_found());
                        } else {
                            destroyed.push(destroy_id);
                        }
                    }

                    response.destroyed = destroyed;
                }
            }
        }

        // Update state
        if !changes.is_empty() || !response.created.is_empty() {
            let new_state = if !changes.is_empty() {
                self.commit_changes(account_id, changes).await?.into()
            } else {
                self.get_state(account_id, Collection::Email).await?
            };
            if let State::Exact(change_id) = &new_state {
                response.state_change = StateChange::new(account_id)
                    .with_change(DataType::Email, *change_id)
                    .with_change(DataType::Mailbox, *change_id)
                    .with_change(DataType::Thread, *change_id)
                    .into();
            }

            response.new_state = new_state.into();
        }

        Ok(response)
    }
}
pub struct TagManager<
    T: PartialEq + Clone + ToBitmaps + SerializeInto + Serialize + DeserializeFrom + Sync + Send,
> {
    current: HashedValue<Vec<T>>,
    added: Vec<T>,
    removed: Vec<T>,
    last: LastTag,
}

enum LastTag {
    Set,
    Update,
    None,
}

impl<
        T: PartialEq + Clone + ToBitmaps + SerializeInto + Serialize + DeserializeFrom + Sync + Send,
    > TagManager<T>
{
    pub fn new(current: HashedValue<Vec<T>>) -> Self {
        Self {
            current,
            added: Vec::new(),
            removed: Vec::new(),
            last: LastTag::None,
        }
    }

    pub fn set(&mut self, tags: Vec<T>) {
        if matches!(self.last, LastTag::None) {
            self.added.clear();
            self.removed.clear();

            for tag in &tags {
                if !self.current.inner.contains(tag) {
                    self.added.push(tag.clone());
                }
            }

            for tag in &self.current.inner {
                if !tags.contains(tag) {
                    self.removed.push(tag.clone());
                }
            }

            self.current.inner = tags;
            self.last = LastTag::Set;
        }
    }

    pub fn update(&mut self, tag: T, add: bool) {
        if matches!(self.last, LastTag::None | LastTag::Update) {
            if add {
                if !self.current.inner.contains(&tag) {
                    self.added.push(tag.clone());
                    self.current.inner.push(tag);
                }
            } else if let Some(index) = self.current.inner.iter().position(|t| t == &tag) {
                self.current.inner.swap_remove(index);
                self.removed.push(tag);
            }
            self.last = LastTag::Update;
        }
    }

    pub fn added(&self) -> &[T] {
        &self.added
    }

    pub fn removed(&self) -> &[T] {
        &self.removed
    }

    pub fn current(&self) -> &[T] {
        &self.current.inner
    }

    pub fn changed_tags(&self) -> impl Iterator<Item = &T> {
        self.added.iter().chain(self.removed.iter())
    }

    pub fn inner_tags_mut(&mut self) -> IterMut<'_, T> {
        self.current.inner.iter_mut()
    }

    pub fn has_tags(&self) -> bool {
        !self.current.inner.is_empty()
    }

    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }

    pub fn update_batch(self, batch: &mut BatchBuilder, property: Property) {
        let property = u8::from(property);

        batch
            .assert_value(ValueClass::Property(property), &self.current)
            .value(property, self.current.inner, F_VALUE);
        for added in self.added {
            batch.value(property, added, F_BITMAP);
        }
        for removed in self.removed {
            batch.value(property, removed, F_BITMAP | F_CLEAR);
        }
    }
}
