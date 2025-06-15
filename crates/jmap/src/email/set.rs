/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::HashMap};

use super::headers::{BuildHeader, ValueToHeader};
use crate::{JmapMethods, blob::download::BlobDownload, changes::state::MessageCacheState};
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    mailbox::UidMailbox,
    message::{
        delete::EmailDeletion,
        ingest::{EmailIngest, IngestEmail, IngestSource},
        metadata::MessageData,
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{RequestArguments, SetRequest, SetResponse},
    response::references::EvalObjectReferences,
    types::{
        acl::Acl,
        collection::{Collection, SyncCollection, VanishedCollection},
        keyword::Keyword,
        property::Property,
        state::{State, StateChange},
        type_state::DataType,
        value::{MaybePatchValue, SetValue, Value},
    },
};
use mail_builder::{
    MessageBuilder,
    headers::{
        HeaderType, address::Address, content_type::ContentType, date::Date, message_id::MessageId,
        raw::Raw, text::Text,
    },
    mime::{BodyPart, MimePart},
};
use mail_parser::MessageParser;
use std::future::Future;
use store::{ahash::AHashMap, roaring::RoaringBitmap, write::BatchBuilder};
use trc::AddContext;

pub trait EmailSet: Sync + Send {
    fn email_set(
        &self,
        request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;
}

impl EmailSet for Server {
    async fn email_set(
        &self,
        mut request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let cache = self.get_cached_messages(account_id).await?;
        let mut response = self
            .prepare_set_response(&request, cache.assert_state(false, &request.if_in_state)?)
            .await?;
        let can_train_spam = self.email_bayes_can_train(access_token);

        // Obtain mailboxIds
        let (can_add_mailbox_ids, can_delete_mailbox_ids, can_modify_message_ids) =
            if access_token.is_shared(account_id) {
                (
                    cache.shared_mailboxes(access_token, Acl::AddItems).into(),
                    cache
                        .shared_mailboxes(access_token, Acl::RemoveItems)
                        .into(),
                    cache.shared_messages(access_token, Acl::ModifyItems).into(),
                )
            } else {
                (None, None, None)
            };

        let mut last_change_id = None;
        let will_destroy = request.unwrap_destroy();

        // Obtain quota
        let resource_token = self.get_resource_token(access_token, account_id).await?;

        // Process creates
        'create: for (id, mut object) in request.unwrap_create() {
            let has_body_structure = object
                .0
                .keys()
                .any(|key| matches!(key, Property::BodyStructure));
            let mut builder = MessageBuilder::new();
            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            // Parse body values
            let body_values = object.0.remove(&Property::BodyValues).and_then(|obj| {
                if let SetValue::Value(Value::Object(obj)) = obj {
                    let mut values = HashMap::with_capacity(obj.0.len());
                    for (key, value) in obj.0 {
                        if let (Property::_T(id), Value::Object(mut bv)) = (key, value) {
                            values.insert(id, bv.0.remove(&Property::Value)?.try_unwrap_string()?);
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
            for (property, value) in object.0 {
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
                                    for (body_property, value) in obj.0 {
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
                                    .is_some_and(|v| v != &content_type)
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
                if !cache.has_mailbox_id(mailbox_id) {
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
                    resource: resource_token.clone(),
                    mailbox_ids: mailboxes,
                    keywords,
                    received_at,
                    source: IngestSource::Jmap,
                    spam_classify: false,
                    spam_train: can_train_spam,
                    session_id: session.session_id,
                })
                .await
            {
                Ok(message) => {
                    last_change_id = message.change_id.into();
                    response.created.insert(id, message.into());
                }
                Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::OverQuota)
                            .with_description("You have exceeded your disk quota."),
                    );
                }
                Err(err) => return Err(err),
            }
        }

        // Process updates
        let mut batch = BatchBuilder::new();
        let mut changed_mailboxes: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let mut will_update = Vec::with_capacity(request.update.as_ref().map_or(0, |u| u.len()));
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain message data
            let document_id = id.document_id();
            let data_ = match self
                .get_archive(account_id, Collection::Email, document_id)
                .await?
            {
                Some(data) => data,
                None => {
                    response.not_updated.append(id, SetError::not_found());
                    continue 'update;
                }
            };
            let data = data_
                .to_unarchived::<MessageData>()
                .caused_by(trc::location!())?;
            let mut new_data = data
                .deserialize::<MessageData>()
                .caused_by(trc::location!())?;

            for (property, value) in object.0 {
                let value = match response.eval_object_references(value) {
                    Ok(value) => value,
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };
                match (property, value) {
                    (Property::MailboxIds, MaybePatchValue::Value(Value::List(ids))) => {
                        new_data.set_mailboxes(
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
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                new_data.add_mailbox(UidMailbox::new_unassigned(id.document_id()));
                            } else {
                                new_data.remove_mailbox(id.document_id());
                            }
                        }
                    }
                    (Property::Keywords, MaybePatchValue::Value(Value::List(keywords_))) => {
                        new_data.set_keywords(
                            keywords_
                                .into_iter()
                                .filter_map(|keyword| keyword.try_unwrap_keyword())
                                .collect(),
                        );
                    }
                    (Property::Keywords, MaybePatchValue::Patch(patch)) => {
                        let mut patch = patch.into_iter();
                        if let Some(keyword) = patch.next().unwrap().try_unwrap_keyword() {
                            if patch.next().unwrap().try_unwrap_bool().unwrap_or_default() {
                                new_data.add_keyword(keyword);
                            } else {
                                new_data.remove_keyword(&keyword);
                            }
                        }
                    }
                    (property, _) => {
                        response.invalid_property_update(id, property);
                        continue 'update;
                    }
                }
            }

            let has_keyword_changes = new_data.has_keyword_changes(data.inner);
            let has_mailbox_changes = new_data.has_mailbox_changes(data.inner);
            if !has_keyword_changes && !has_mailbox_changes {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("No changes found in request.".to_string()),
                );
                continue 'update;
            }

            // Process keywords
            if has_keyword_changes {
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
                if new_data
                    .added_keywords(data.inner)
                    .any(|keyword| keyword == &Keyword::Seen)
                    || new_data
                        .removed_keywords(data.inner)
                        .any(|keyword| keyword == &Keyword::Seen)
                {
                    for mailbox_id in new_data.mailboxes.iter() {
                        changed_mailboxes.insert(mailbox_id.mailbox_id, Vec::new());
                    }
                }
            }

            // Process mailboxes
            if has_mailbox_changes {
                // Make sure the message is at least in one mailbox
                if new_data.mailboxes.is_empty() {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
                            .with_description("Message has to belong to at least one mailbox."),
                    );
                    continue 'update;
                }

                // Make sure all new mailboxIds are valid
                for mailbox_id in new_data.added_mailboxes(data.inner) {
                    if cache.has_mailbox_id(&mailbox_id.mailbox_id) {
                        // Verify permissions on shared accounts
                        if !matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(mailbox_id.mailbox_id))
                        {
                            changed_mailboxes.insert(mailbox_id.mailbox_id, Vec::new());
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
                for mailbox_id in new_data.removed_mailboxes(data.inner) {
                    // Verify permissions on shared accounts
                    if !matches!(&can_delete_mailbox_ids, Some(ids) if !ids.contains(u32::from(mailbox_id.mailbox_id)))
                    {
                        changed_mailboxes
                            .entry(mailbox_id.mailbox_id.to_native())
                            .or_default()
                            .push(mailbox_id.uid.to_native());
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
                for uid_mailbox in &mut new_data.mailboxes {
                    if uid_mailbox.uid == 0 {
                        uid_mailbox.uid = self
                            .assign_imap_uid(account_id, uid_mailbox.mailbox_id)
                            .await
                            .caused_by(trc::location!())?;
                    }
                }
            }

            // Write changes
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .update_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(data)
                        .with_changes(new_data),
                )
                .caused_by(trc::location!())?
                .commit_point();
            will_update.push(id);
        }

        if !batch.is_empty() {
            // Log mailbox changes
            for (parent_id, deleted_uids) in changed_mailboxes {
                batch.log_container_property_change(SyncCollection::Email, parent_id);
                for deleted_uid in deleted_uids {
                    batch.log_vanished_item(VanishedCollection::Email, (parent_id, deleted_uid));
                }
            }

            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id) => {
                    last_change_id = change_id.into();

                    // Add to updated list
                    for id in will_update {
                        response.updated.append(id, None);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for id in will_update {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this message, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        // Process deletions
        if !will_destroy.is_empty() {
            let email_ids = cache.email_document_ids();
            let can_destroy_message_ids = if access_token.is_shared(account_id) {
                cache.shared_messages(access_token, Acl::RemoveItems).into()
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
                let mut batch = BatchBuilder::new();
                let not_destroyed = self
                    .emails_tombstone(account_id, &mut batch, destroy_ids)
                    .await?;
                if !batch.is_empty() {
                    last_change_id = self
                        .commit_batch(batch)
                        .await
                        .and_then(|ids| ids.last_change_id(account_id))
                        .caused_by(trc::location!())?
                        .into();
                }

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
        if let Some(change_id) = last_change_id {
            if response.updated.is_empty() && response.destroyed.is_empty() {
                // Message ingest does not broadcast state changes
                self.broadcast_state_change(
                    StateChange::new(account_id, change_id)
                        .with_change(DataType::Email)
                        .with_change(DataType::Mailbox)
                        .with_change(DataType::Thread),
                )
                .await;
            }

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}
