/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::metadata::{
    ArchivedMessageData, ArchivedMessageMetadata, ArchivedMessageMetadataContents,
    ArchivedMessageMetadataPart, ArchivedMetadataPartType, DecodedPartContent, MessageData,
    MessageMetadata, MessageMetadataPart,
};
use common::storage::index::{IndexValue, IndexableObject, ObjectIndexBuilder};
use jmap_proto::types::{collection::SyncCollection, property::Property};
use mail_parser::{
    Addr, Address, ArchivedAddress, ArchivedHeaderName, ArchivedHeaderValue, Group, HeaderName,
    HeaderValue,
    core::rkyv::ArchivedGetHeader,
    decoders::html::html_to_text,
    parsers::{fields::thread::thread_name, preview::preview_text},
};
use nlp::language::Language;
use rkyv::option::ArchivedOption;
use store::{
    Serialize, SerializeInfallible,
    backend::MAX_TOKEN_LENGTH,
    fts::{Field, index::FtsDocument},
    write::{Archiver, BatchBuilder, BlobOp, DirectoryClass},
};
use trc::AddContext;
use utils::BlobHash;

pub const MAX_MESSAGE_PARTS: usize = 1000;
pub const MAX_ID_LENGTH: usize = 100;
pub const MAX_SORT_FIELD_LENGTH: usize = 255;
pub const MAX_STORED_FIELD_LENGTH: usize = 512;
pub const PREVIEW_LENGTH: usize = 256;

impl MessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &MessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn index(
        self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
        set: bool,
    ) -> trc::Result<()> {
        if set {
            // Serialize metadata
            batch
                .index(Property::Size, self.size.serialize())
                .index(Property::ReceivedAt, (self.received_at).serialize());
        } else {
            // Delete metadata
            batch
                .clear(Property::BodyStructure)
                .unindex(Property::Size, self.size.serialize())
                .unindex(Property::ReceivedAt, (self.received_at).serialize());
        }

        // Index properties
        let quota = if set {
            self.size as i64
        } else {
            -(self.size as i64)
        };
        batch.add(DirectoryClass::UsedQuota(account_id), quota);
        if let Some(tenant_id) = tenant_id {
            batch.add(DirectoryClass::UsedQuota(tenant_id), quota);
        }

        if self.has_attachments {
            if set {
                batch.tag(Property::HasAttachment, ());
            } else {
                batch.untag(Property::HasAttachment, ());
            }
        }

        // Index headers
        self.index_headers(batch, set);

        // Link blob
        if set {
            batch.set(
                BlobOp::Link {
                    hash: self.blob_hash.clone(),
                },
                Vec::new(),
            );
        } else {
            batch.clear(BlobOp::Link {
                hash: self.blob_hash.clone(),
            });
        }

        if set {
            batch.set(Property::BodyStructure, Archiver::new(self).serialize()?);
        }

        Ok(())
    }

    fn index_headers(&self, batch: &mut BatchBuilder, set: bool) {
        let mut seen_headers = [false; 40];
        for header in self.root_part().headers.iter().rev() {
            if matches!(header.name, HeaderName::Other(_)) {
                continue;
            }

            match header.name {
                HeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                batch.index(Property::References, encode_message_id(id));
                            } else {
                                batch.unindex(Property::References, encode_message_id(id));
                            }
                        }
                    });
                }
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                batch.index(Property::References, id.serialize());
                            } else {
                                batch.unindex(Property::References, id.serialize());
                            }
                        }
                    });
                }
                HeaderName::From | HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    if !seen_headers[header.name.id() as usize] {
                        let property = property_from_header(&header.name);
                        let mut sort_text = SortedAddressBuilder::new();
                        let mut found_addr = false;

                        header.value.visit_addresses(|element, value| {
                            if !found_addr {
                                match element {
                                    AddressElement::Name => {
                                        found_addr = !sort_text.push(value);
                                    }
                                    AddressElement::Address => {
                                        sort_text.push(value);
                                        found_addr = true;
                                    }
                                    AddressElement::GroupName => (),
                                }
                            }
                        });

                        // Add address to inverted index
                        if set {
                            batch.index(u8::from(&property), sort_text.build());
                        } else {
                            batch.unindex(u8::from(&property), sort_text.build());
                        }
                        seen_headers[header.name.id() as usize] = true;
                    }
                }
                HeaderName::Date => {
                    if !seen_headers[header.name.id() as usize] {
                        if let HeaderValue::DateTime(datetime) = &header.value {
                            let value = (datetime.to_timestamp() as u64).serialize();
                            if set {
                                batch.index(Property::SentAt, value);
                            } else {
                                batch.unindex(Property::SentAt, value);
                            }
                        }
                        seen_headers[header.name.id() as usize] = true;
                    }
                }
                HeaderName::Subject => {
                    if !seen_headers[header.name.id() as usize] {
                        // Index subject
                        let subject = match &header.value {
                            HeaderValue::Text(text) => text.clone(),
                            HeaderValue::TextList(list) if !list.is_empty() => {
                                list.first().unwrap().clone()
                            }
                            _ => "".into(),
                        };

                        // Index thread name
                        let thread_name = thread_name(&subject);
                        let thread_name = if !thread_name.is_empty() {
                            thread_name.trim_text(MAX_SORT_FIELD_LENGTH)
                        } else {
                            "!"
                        }
                        .serialize();

                        if set {
                            batch.index(Property::Subject, thread_name);
                        } else {
                            batch.unindex(Property::Subject, thread_name);
                        }

                        seen_headers[header.name.id() as usize] = true;
                    }
                }

                _ => (),
            }
        }

        // Add subject to index if missing
        if !seen_headers[HeaderName::Subject.id() as usize] {
            if set {
                batch.index(Property::Subject, "!".serialize());
            } else {
                batch.unindex(Property::Subject, "!".serialize());
            }
        }
    }
}

fn encode_message_id(message_id: &str) -> Vec<u8> {
    let mut msg_id = Vec::with_capacity(message_id.len() + 1);
    msg_id.extend_from_slice(message_id.as_bytes());
    msg_id.push(0);
    msg_id
}

impl ArchivedMessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn index(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
        set: bool,
    ) -> trc::Result<()> {
        if set {
            // Serialize metadata
            batch
                .index(Property::Size, u32::from(self.size).serialize())
                .index(
                    Property::ReceivedAt,
                    u64::from(self.received_at).serialize(),
                );
        } else {
            // Delete metadata
            batch
                .clear(Property::BodyStructure)
                .unindex(Property::Size, u32::from(self.size).serialize())
                .unindex(
                    Property::ReceivedAt,
                    u64::from(self.received_at).serialize(),
                );
        }

        // Index properties
        let quota = if set {
            u32::from(self.size) as i64
        } else {
            -(u32::from(self.size) as i64)
        };
        batch.add(DirectoryClass::UsedQuota(account_id), quota);
        if let Some(tenant_id) = tenant_id {
            batch.add(DirectoryClass::UsedQuota(tenant_id), quota);
        }

        if self.has_attachments {
            if set {
                batch.tag(Property::HasAttachment, ());
            } else {
                batch.untag(Property::HasAttachment, ());
            }
        }

        // Index headers
        self.index_headers(batch, set);

        // Link blob
        let hash = BlobHash::from(&self.blob_hash);
        if set {
            batch.set(BlobOp::Link { hash }, Vec::new());
        } else {
            batch.clear(BlobOp::Link { hash });
        }

        Ok(())
    }

    fn index_headers(&self, batch: &mut BatchBuilder, set: bool) {
        let mut seen_headers = [false; 40];
        for header in self.root_part().headers.iter().rev() {
            if matches!(header.name, ArchivedHeaderName::Other(_)) {
                continue;
            }

            match header.name {
                ArchivedHeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                batch.index(Property::References, encode_message_id(id));
                            } else {
                                batch.unindex(Property::References, encode_message_id(id));
                            }
                        }
                    });
                }
                ArchivedHeaderName::InReplyTo
                | ArchivedHeaderName::References
                | ArchivedHeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                batch.index(Property::References, id.serialize());
                            } else {
                                batch.unindex(Property::References, id.serialize());
                            }
                        }
                    });
                }
                ArchivedHeaderName::From
                | ArchivedHeaderName::To
                | ArchivedHeaderName::Cc
                | ArchivedHeaderName::Bcc => {
                    if !seen_headers[header.name.id() as usize] {
                        let property = property_from_archived_header(&header.name);
                        let mut sort_text = SortedAddressBuilder::new();
                        let mut found_addr = false;

                        header.value.visit_addresses(|element, value| {
                            if !found_addr {
                                match element {
                                    AddressElement::Name => {
                                        found_addr = !sort_text.push(value);
                                    }
                                    AddressElement::Address => {
                                        sort_text.push(value);
                                        found_addr = true;
                                    }
                                    AddressElement::GroupName => (),
                                }
                            }
                        });

                        // Add address to inverted index
                        if set {
                            batch.index(u8::from(&property), sort_text.build());
                        } else {
                            batch.unindex(u8::from(&property), sort_text.build());
                        }
                        seen_headers[header.name.id() as usize] = true;
                    }
                }
                ArchivedHeaderName::Date => {
                    if !seen_headers[header.name.id() as usize] {
                        if let ArchivedHeaderValue::DateTime(datetime) = &header.value {
                            let value = (mail_parser::DateTime::from(datetime).to_timestamp()
                                as u64)
                                .serialize();
                            if set {
                                batch.index(Property::SentAt, value);
                            } else {
                                batch.unindex(Property::SentAt, value);
                            }
                        }
                        seen_headers[header.name.id() as usize] = true;
                    }
                }
                ArchivedHeaderName::Subject => {
                    if !seen_headers[header.name.id() as usize] {
                        // Index subject
                        let subject = match &header.value {
                            ArchivedHeaderValue::Text(text) => text.as_str(),
                            ArchivedHeaderValue::TextList(list) if !list.is_empty() => {
                                list.first().unwrap().as_str()
                            }
                            _ => "",
                        };

                        // Index thread name
                        let thread_name = thread_name(subject);
                        let thread_name = if !thread_name.is_empty() {
                            thread_name.trim_text(MAX_SORT_FIELD_LENGTH)
                        } else {
                            "!"
                        }
                        .serialize();

                        if set {
                            batch.index(Property::Subject, thread_name);
                        } else {
                            batch.unindex(Property::Subject, thread_name);
                        }

                        seen_headers[header.name.id() as usize] = true;
                    }
                }

                _ => (),
            }
        }

        // Add subject to index if missing
        if !seen_headers[HeaderName::Subject.id() as usize] {
            if set {
                batch.index(Property::Subject, "!".serialize());
            } else {
                batch.unindex(Property::Subject, "!".serialize());
            }
        }
    }
}

impl ArchivedMessageMetadataContents {
    pub fn is_html_part(&self, part_id: u16) -> bool {
        self.html_body.iter().any(|&id| id == part_id)
    }

    pub fn is_text_part(&self, part_id: u16) -> bool {
        self.text_body.iter().any(|&id| id == part_id)
    }
}
#[derive(Debug)]
pub struct SortedAddressBuilder {
    last_is_space: bool,
    pub buf: String,
}

pub(super) trait IndexMessage {
    #[allow(clippy::too_many_arguments)]
    fn index_message(
        &mut self,
        account_id: u32,
        tenant_id: Option<u32>,
        message: mail_parser::Message<'_>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self>;
}

impl IndexMessage for BatchBuilder {
    fn index_message(
        &mut self,
        account_id: u32,
        tenant_id: Option<u32>,
        message: mail_parser::Message<'_>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self> {
        // Index size
        self.index(
            Property::Size,
            (message.raw_message.len() as u32).serialize(),
        )
        .add(
            DirectoryClass::UsedQuota(account_id),
            message.raw_message.len() as i64,
        );
        if let Some(tenant_id) = tenant_id {
            self.add(
                DirectoryClass::UsedQuota(tenant_id),
                message.raw_message.len() as i64,
            );
        }

        // Index receivedAt
        self.index(Property::ReceivedAt, received_at.serialize());

        let mut has_attachments = false;
        let mut preview = None;
        let preview_part_id = message
            .text_body
            .first()
            .or_else(|| message.html_body.first())
            .copied()
            .unwrap_or(u32::MAX);

        for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
            let part_id = part_id as u32;
            match &part.body {
                mail_parser::PartType::Text(text) => {
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Html(html) => {
                    let text = html_to_text(html);
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Binary(_) | mail_parser::PartType::Message(_)
                    if !has_attachments =>
                {
                    has_attachments = true;
                }
                _ => {}
            }
        }

        // Build metadata
        let root_part = message.root_part();
        let metadata = MessageMetadata {
            preview: preview.unwrap_or_default().into_owned(),
            size: message.raw_message.len() as u32,
            raw_headers: message
                .raw_message
                .as_ref()
                .get(root_part.offset_header as usize..root_part.offset_body as usize)
                .unwrap_or_default()
                .to_vec(),
            contents: vec![],
            received_at,
            has_attachments,
            blob_hash,
        }
        .with_contents(message);
        metadata.index_headers(self, true);

        // Store and index hasAttachment property
        if has_attachments {
            self.tag(Property::HasAttachment, ());
        }

        // Link blob
        self.set(
            BlobOp::Link {
                hash: metadata.blob_hash.clone(),
            },
            Vec::new(),
        );

        // Store message data
        self.custom(ObjectIndexBuilder::<(), _>::new().with_changes(data))
            .caused_by(trc::location!())?;

        // Store message metadata
        self.set(
            Property::BodyStructure,
            Archiver::new(metadata)
                .serialize()
                .caused_by(trc::location!())?,
        );

        Ok(self)
    }
}

impl IndexableObject for MessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email.into(),
                prefix: self.thread_id.into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread.into(),
                ids: vec![self.thread_id],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email.into(),
                ids: self.mailboxes.iter().map(|m| m.mailbox_id).collect(),
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedMessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email.into(),
                prefix: self.thread_id.to_native().into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread.into(),
                ids: vec![self.thread_id.to_native()],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email.into(),
                ids: self
                    .mailboxes
                    .iter()
                    .map(|m| m.mailbox_id.to_native())
                    .collect(),
            },
        ]
        .into_iter()
    }
}

pub trait IndexMessageText<'x>: Sized {
    fn index_message(self, message: &'x ArchivedMessageMetadata, raw_message: &'x [u8]) -> Self;
}

impl<'x> IndexMessageText<'x> for FtsDocument<'x, mail_parser::HeaderName<'x>> {
    fn index_message(
        mut self,
        message: &'x ArchivedMessageMetadata,
        raw_message: &'x [u8],
    ) -> Self {
        let mut language = Language::Unknown;
        let message_contents = &message.contents[0];

        for (part_id, part) in message_contents
            .parts
            .iter()
            .take(MAX_MESSAGE_PARTS)
            .enumerate()
        {
            let part_language = part.language().unwrap_or(language);
            if part_id == 0 {
                language = part_language;

                for header in part.headers.iter().rev() {
                    if matches!(header.name, ArchivedHeaderName::Other(_)) {
                        continue;
                    }
                    // Index hasHeader property
                    self.index_keyword(Field::Keyword, header.name.as_str().to_ascii_lowercase());

                    match &header.name {
                        ArchivedHeaderName::MessageId
                        | ArchivedHeaderName::InReplyTo
                        | ArchivedHeaderName::References
                        | ArchivedHeaderName::ResentMessageId => {
                            header.value.visit_text(|id| {
                                // Index ids without stemming
                                if id.len() < MAX_TOKEN_LENGTH {
                                    self.index_keyword(
                                        Field::Header(mail_parser::HeaderName::from(&header.name)),
                                        id.to_string(),
                                    );
                                }
                            });
                        }
                        ArchivedHeaderName::From
                        | ArchivedHeaderName::To
                        | ArchivedHeaderName::Cc
                        | ArchivedHeaderName::Bcc => {
                            header.value.visit_addresses(|_, value| {
                                // Index an address name or email without stemming
                                self.index_tokenized(
                                    Field::Header(mail_parser::HeaderName::from(&header.name)),
                                    value.to_string(),
                                );
                            });
                        }
                        ArchivedHeaderName::Subject => {
                            // Index subject for FTS
                            if let Some(subject) = header.value.as_text() {
                                self.index(
                                    Field::Header(mail_parser::HeaderName::Subject),
                                    subject,
                                    language,
                                );
                            }
                        }
                        ArchivedHeaderName::Comments
                        | ArchivedHeaderName::Keywords
                        | ArchivedHeaderName::ListId => {
                            // Index headers
                            header.value.visit_text(|text| {
                                self.index_tokenized(
                                    Field::Header(mail_parser::HeaderName::from(&header.name)),
                                    text.to_string(),
                                );
                            });
                        }
                        _ => (),
                    }
                }
            }

            let part_id = part_id as u16;
            match &part.body {
                ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                    let text = match (part.decode_contents(raw_message), &part.body) {
                        (DecodedPartContent::Text(text), ArchivedMetadataPartType::Text) => text,
                        (DecodedPartContent::Text(html), ArchivedMetadataPartType::Html) => {
                            html_to_text(html.as_ref()).into()
                        }
                        _ => unreachable!(),
                    };

                    if message_contents.is_html_part(part_id)
                        || message_contents.is_text_part(part_id)
                    {
                        self.index(Field::Body, text, part_language);
                    } else {
                        self.index(Field::Attachment, text, part_language);
                    }
                }
                ArchivedMetadataPartType::Message(nested_message_id) => {
                    let nested_message = message.message_id(*nested_message_id);
                    let nested_message_language = nested_message
                        .root_part()
                        .language()
                        .unwrap_or(Language::Unknown);
                    if let Some(ArchivedHeaderValue::Text(subject)) = nested_message
                        .root_part()
                        .headers
                        .header_value(&ArchivedHeaderName::Subject)
                    {
                        self.index(Field::Attachment, subject.as_ref(), nested_message_language);
                    }

                    for sub_part in nested_message.parts.iter().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_message_language);
                        match &sub_part.body {
                            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                                let text =
                                    match (sub_part.decode_contents(raw_message), &sub_part.body) {
                                        (
                                            DecodedPartContent::Text(text),
                                            ArchivedMetadataPartType::Text,
                                        ) => text,
                                        (
                                            DecodedPartContent::Text(html),
                                            ArchivedMetadataPartType::Html,
                                        ) => html_to_text(html.as_ref()).into(),
                                        _ => unreachable!(),
                                    };
                                self.index(Field::Attachment, text, language);
                            }
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }
        self
    }
}

impl SortedAddressBuilder {
    pub fn new() -> Self {
        Self {
            last_is_space: true,
            buf: String::with_capacity(32),
        }
    }

    pub fn push(&mut self, text: &str) -> bool {
        if !text.is_empty() {
            if !self.buf.is_empty() {
                self.buf.push(' ');
                self.last_is_space = true;
            }
            for ch in text.chars() {
                for ch in ch.to_lowercase() {
                    if self.buf.len() < MAX_SORT_FIELD_LENGTH {
                        let is_space = ch.is_whitespace();
                        if !is_space || !self.last_is_space {
                            self.buf.push(ch);
                            self.last_is_space = is_space;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn build(self) -> String {
        if !self.buf.is_empty() {
            self.buf
        } else {
            "!".to_string()
        }
    }
}

impl Default for SortedAddressBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchivedMessageMetadataPart {
    fn language(&self) -> Option<Language> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentLanguage)
            .and_then(|v| {
                Language::from_iso_639(match v {
                    ArchivedHeaderValue::Text(v) => v.as_ref(),
                    ArchivedHeaderValue::TextList(v) => v.first()?,
                    _ => {
                        return None;
                    }
                })
                .unwrap_or(Language::Unknown)
                .into()
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressElement {
    Name,
    Address,
    GroupName,
}

pub trait VisitText {
    fn visit_addresses(&self, visitor: impl FnMut(AddressElement, &str));
    fn visit_text<'x>(&'x self, visitor: impl FnMut(&'x str));
    fn into_visit_text(self, visitor: impl FnMut(String));
}

impl VisitText for HeaderValue<'_> {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        match self {
            HeaderValue::Address(Address::List(addr_list)) => {
                for addr in addr_list {
                    if let Some(name) = &addr.name {
                        visitor(AddressElement::Name, name);
                    }
                    if let Some(addr) = &addr.address {
                        visitor(AddressElement::Address, addr);
                    }
                }
            }
            HeaderValue::Address(Address::Group(groups)) => {
                for group in groups {
                    if let Some(name) = &group.name {
                        visitor(AddressElement::GroupName, name);
                    }

                    for addr in &group.addresses {
                        if let Some(name) = &addr.name {
                            visitor(AddressElement::Name, name);
                        }
                        if let Some(addr) = &addr.address {
                            visitor(AddressElement::Address, addr);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    fn visit_text<'x>(&'x self, mut visitor: impl FnMut(&'x str)) {
        match &self {
            HeaderValue::Text(text) => {
                visitor(text.as_ref());
            }
            HeaderValue::TextList(texts) => {
                for text in texts {
                    visitor(text.as_ref());
                }
            }
            _ => (),
        }
    }

    fn into_visit_text(self, mut visitor: impl FnMut(String)) {
        match self {
            HeaderValue::Text(text) => {
                visitor(text.into_owned());
            }
            HeaderValue::TextList(texts) => {
                for text in texts {
                    visitor(text.into_owned());
                }
            }
            _ => (),
        }
    }
}

pub trait VisitTextArchived {
    fn visit_addresses(&self, visitor: impl FnMut(AddressElement, &str));
    fn visit_text(&self, visitor: impl FnMut(&str));
}

impl VisitTextArchived for ArchivedHeaderValue<'static> {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        match self {
            ArchivedHeaderValue::Address(ArchivedAddress::List(addr_list)) => {
                for addr in addr_list.iter() {
                    if let ArchivedOption::Some(name) = &addr.name {
                        visitor(AddressElement::Name, name);
                    }
                    if let ArchivedOption::Some(addr) = &addr.address {
                        visitor(AddressElement::Address, addr);
                    }
                }
            }
            ArchivedHeaderValue::Address(ArchivedAddress::Group(groups)) => {
                for group in groups.iter() {
                    if let ArchivedOption::Some(name) = &group.name {
                        visitor(AddressElement::GroupName, name);
                    }

                    for addr in group.addresses.iter() {
                        if let ArchivedOption::Some(name) = &addr.name {
                            visitor(AddressElement::Name, name);
                        }
                        if let ArchivedOption::Some(addr) = &addr.address {
                            visitor(AddressElement::Address, addr);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    fn visit_text(&self, mut visitor: impl FnMut(&str)) {
        match &self {
            ArchivedHeaderValue::Text(text) => {
                visitor(text.as_ref());
            }
            ArchivedHeaderValue::TextList(texts) => {
                for text in texts.iter() {
                    visitor(text.as_ref());
                }
            }
            _ => (),
        }
    }
}

pub trait TrimTextValue {
    fn trim_text(self, length: usize) -> Self;
}

impl TrimTextValue for HeaderValue<'_> {
    fn trim_text(self, length: usize) -> Self {
        match self {
            HeaderValue::Address(Address::List(v)) => {
                HeaderValue::Address(Address::List(v.trim_text(length)))
            }
            HeaderValue::Address(Address::Group(v)) => {
                HeaderValue::Address(Address::Group(v.trim_text(length)))
            }
            HeaderValue::Text(v) => HeaderValue::Text(v.trim_text(length)),
            HeaderValue::TextList(v) => HeaderValue::TextList(v.trim_text(length)),
            v => v,
        }
    }
}

impl TrimTextValue for Addr<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            address: self.address.map(|v| v.trim_text(length)),
        }
    }
}

impl TrimTextValue for Group<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            addresses: self.addresses.trim_text(length),
        }
    }
}

impl TrimTextValue for &str {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut index = 0;

            for (i, _) in self.char_indices() {
                if i > length {
                    break;
                }
                index = i;
            }

            &self[..index]
        }
    }
}

impl TrimTextValue for Cow<'_, str> {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut result = String::with_capacity(length);
            for (i, c) in self.char_indices() {
                if i > length {
                    break;
                }
                result.push(c);
            }
            result.into()
        }
    }
}

impl<T: TrimTextValue> TrimTextValue for Vec<T> {
    fn trim_text(self, length: usize) -> Self {
        self.into_iter().map(|v| v.trim_text(length)).collect()
    }
}

pub fn property_from_header(header: &HeaderName) -> Property {
    match header {
        HeaderName::Subject => Property::Subject,
        HeaderName::From => Property::From,
        HeaderName::To => Property::To,
        HeaderName::Cc => Property::Cc,
        HeaderName::Date => Property::SentAt,
        HeaderName::Bcc => Property::Bcc,
        HeaderName::ReplyTo => Property::ReplyTo,
        HeaderName::Sender => Property::Sender,
        HeaderName::InReplyTo => Property::InReplyTo,
        HeaderName::MessageId => Property::MessageId,
        HeaderName::References => Property::References,
        HeaderName::ResentMessageId => Property::EmailIds,
        _ => unreachable!(),
    }
}

pub fn property_from_archived_header(header: &ArchivedHeaderName) -> Property {
    match header {
        ArchivedHeaderName::Subject => Property::Subject,
        ArchivedHeaderName::From => Property::From,
        ArchivedHeaderName::To => Property::To,
        ArchivedHeaderName::Cc => Property::Cc,
        ArchivedHeaderName::Date => Property::SentAt,
        ArchivedHeaderName::Bcc => Property::Bcc,
        ArchivedHeaderName::ReplyTo => Property::ReplyTo,
        ArchivedHeaderName::Sender => Property::Sender,
        ArchivedHeaderName::InReplyTo => Property::InReplyTo,
        ArchivedHeaderName::MessageId => Property::MessageId,
        ArchivedHeaderName::References => Property::References,
        ArchivedHeaderName::ResentMessageId => Property::EmailIds,
        _ => unreachable!(),
    }
}
