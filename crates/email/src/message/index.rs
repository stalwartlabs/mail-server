/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use jmap_proto::types::{keyword::Keyword, property::Property};
use mail_parser::{
    Addr, Address, GetHeader, Group, Header, HeaderName, HeaderValue, Message, MessagePart,
    PartType,
    decoders::html::html_to_text,
    parsers::{fields::thread::thread_name, preview::preview_text},
};
use nlp::language::Language;
use store::{
    Serialize, SerializeInfallible,
    backend::MAX_TOKEN_LENGTH,
    fts::{Field, index::FtsDocument},
    write::{BatchBuilder, Bincode, BlobOp, DirectoryClass},
};
use trc::AddContext;
use utils::BlobHash;

use crate::mailbox::UidMailbox;

use super::metadata::MessageMetadata;

pub const MAX_MESSAGE_PARTS: usize = 1000;
pub const MAX_ID_LENGTH: usize = 100;
pub const MAX_SORT_FIELD_LENGTH: usize = 255;
pub const MAX_STORED_FIELD_LENGTH: usize = 512;
pub const PREVIEW_LENGTH: usize = 256;

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
        message: Message,
        blob_hash: BlobHash,
        keywords: Vec<Keyword>,
        mailbox_ids: Vec<UidMailbox>,
        received_at: u64,
    ) -> trc::Result<&mut Self>;

    fn index_headers(&mut self, headers: &[Header<'_>], set: bool);
}

pub trait IndexMessageText<'x>: Sized {
    fn index_message(self, message: &'x Message<'x>) -> Self;
}

impl IndexMessage for BatchBuilder {
    fn index_message(
        &mut self,
        account_id: u32,
        tenant_id: Option<u32>,
        message: Message,
        blob_hash: BlobHash,
        keywords: Vec<Keyword>,
        mailbox_ids: Vec<UidMailbox>,
        received_at: u64,
    ) -> trc::Result<&mut Self> {
        // Index keywords
        self.set(
            Property::Keywords,
            keywords.serialize().caused_by(trc::location!())?,
        )
        .tag_many(Property::Keywords, keywords.into_iter());

        // Index mailboxIds
        self.set(
            Property::MailboxIds,
            mailbox_ids.serialize().caused_by(trc::location!())?,
        )
        .tag_many(Property::MailboxIds, mailbox_ids.iter());

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
            .unwrap_or(usize::MAX);

        for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
            if part_id == 0 {
                self.index_headers(&part.headers, true);
            }

            match &part.body {
                PartType::Text(text) => {
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
                PartType::Html(html) => {
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
                PartType::Binary(_) | PartType::Message(_) if !has_attachments => {
                    has_attachments = true;
                }
                _ => {}
            }
        }

        // Store and index hasAttachment property
        if has_attachments {
            self.tag(Property::HasAttachment, ());
        }

        // Link blob
        self.set(
            BlobOp::Link {
                hash: blob_hash.clone(),
            },
            Vec::new(),
        );

        // Store message metadata
        let root_part = message.root_part();
        self.set(
            Property::BodyStructure,
            Bincode::new(MessageMetadata {
                preview: preview.unwrap_or_default().into_owned(),
                size: message.raw_message.len(),
                raw_headers: message
                    .raw_message
                    .as_ref()
                    .get(root_part.offset_header..root_part.offset_body)
                    .unwrap_or_default()
                    .to_vec(),
                contents: message.into(),
                received_at,
                has_attachments,
                blob_hash,
            })
            .serialize()
            .caused_by(trc::location!())?,
        );

        Ok(self)
    }

    fn index_headers(&mut self, headers: &[Header<'_>], set: bool) {
        let mut seen_headers = [false; 40];
        for header in headers.iter().rev() {
            if matches!(header.name, HeaderName::Other(_)) {
                continue;
            }

            match header.name {
                HeaderName::MessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                self.index(Property::MessageId, id.serialize())
                                    .index(Property::References, id.serialize());
                            } else {
                                self.unindex(Property::MessageId, id.serialize())
                                    .unindex(Property::References, id.serialize());
                            }
                        }
                    });
                }
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    header.value.visit_text(|id| {
                        // Add ids to inverted index
                        if id.len() < MAX_ID_LENGTH {
                            if set {
                                self.index(Property::References, id.serialize());
                            } else {
                                self.unindex(Property::References, id.serialize());
                            }
                        }
                    });
                }
                HeaderName::From | HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    if !seen_headers[header.name.id() as usize] {
                        let property = Property::from_header(&header.name);
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
                            self.index(u8::from(&property), sort_text.build());
                        } else {
                            self.unindex(u8::from(&property), sort_text.build());
                        }
                        seen_headers[header.name.id() as usize] = true;
                    }
                }
                HeaderName::Date => {
                    if !seen_headers[header.name.id() as usize] {
                        if let HeaderValue::DateTime(datetime) = &header.value {
                            let value = (datetime.to_timestamp() as u64).serialize();
                            if set {
                                self.index(Property::SentAt, value);
                            } else {
                                self.unindex(Property::SentAt, value);
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
                            self.index(Property::Subject, thread_name);
                        } else {
                            self.unindex(Property::Subject, thread_name);
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
                self.index(Property::Subject, "!".serialize());
            } else {
                self.unindex(Property::Subject, "!".serialize());
            }
        }
    }
}

impl<'x> IndexMessageText<'x> for FtsDocument<'x, HeaderName<'x>> {
    fn index_message(mut self, message: &'x Message<'x>) -> Self {
        let mut language = Language::Unknown;

        for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
            let part_language = part.language().unwrap_or(language);
            if part_id == 0 {
                language = part_language;

                for header in part.headers.iter().rev() {
                    if matches!(header.name, HeaderName::Other(_)) {
                        continue;
                    }
                    // Index hasHeader property
                    self.index_keyword(Field::Keyword, header.name.as_str().to_ascii_lowercase());

                    match &header.name {
                        HeaderName::MessageId
                        | HeaderName::InReplyTo
                        | HeaderName::References
                        | HeaderName::ResentMessageId => {
                            header.value.visit_text(|id| {
                                // Index ids without stemming
                                if id.len() < MAX_TOKEN_LENGTH {
                                    self.index_keyword(
                                        Field::Header(header.name.clone()),
                                        id.to_string(),
                                    );
                                }
                            });
                        }
                        HeaderName::From | HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                            header.value.visit_addresses(|_, value| {
                                // Index an address name or email without stemming
                                self.index_tokenized(
                                    Field::Header(header.name.clone()),
                                    value.to_string(),
                                );
                            });
                        }
                        HeaderName::Subject => {
                            // Index subject for FTS
                            if let Some(subject) = header.value.as_text() {
                                self.index(Field::Header(HeaderName::Subject), subject, language);
                            }
                        }
                        HeaderName::Comments | HeaderName::Keywords | HeaderName::ListId => {
                            // Index headers
                            header.value.visit_text(|text| {
                                self.index_tokenized(
                                    Field::Header(header.name.clone()),
                                    text.to_string(),
                                );
                            });
                        }
                        _ => (),
                    }
                }
            }

            match &part.body {
                PartType::Text(text) => {
                    if message.text_body.contains(&part_id) || message.html_body.contains(&part_id)
                    {
                        self.index(Field::Body, text.as_ref(), part_language);
                    } else {
                        self.index(Field::Attachment, text.as_ref(), part_language);
                    }
                }
                PartType::Html(html) => {
                    let text = html_to_text(html);

                    if message.text_body.contains(&part_id) || message.html_body.contains(&part_id)
                    {
                        self.index(Field::Body, text, part_language);
                    } else {
                        self.index(Field::Attachment, text, part_language);
                    }
                }
                PartType::Message(nested_message) => {
                    let nested_message_language = nested_message
                        .root_part()
                        .language()
                        .unwrap_or(Language::Unknown);
                    if let Some(HeaderValue::Text(subject)) =
                        nested_message.header(HeaderName::Subject)
                    {
                        self.index(Field::Attachment, subject.as_ref(), nested_message_language);
                    }

                    for sub_part in nested_message.parts.iter().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_message_language);
                        match &sub_part.body {
                            PartType::Text(text) => {
                                self.index(Field::Attachment, text.as_ref(), language);
                            }
                            PartType::Html(html) => {
                                self.index(Field::Attachment, html_to_text(html), language);
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

pub struct EmailIndexBuilder<'x> {
    inner: Bincode<MessageMetadata<'x>>,
    set: bool,
}

impl<'x> EmailIndexBuilder<'x> {
    pub fn set(inner: MessageMetadata<'x>) -> Self {
        Self {
            inner: Bincode { inner },
            set: true,
        }
    }

    pub fn clear(inner: MessageMetadata<'x>) -> Self {
        Self {
            inner: Bincode { inner },
            set: false,
        }
    }
}

impl EmailIndexBuilder<'_> {
    pub fn build(
        self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
    ) -> trc::Result<()> {
        let metadata = &self.inner.inner;
        if self.set {
            // Serialize metadata
            batch
                .set(Property::BodyStructure, (self.inner).serialize()?)
                .index(Property::Size, (metadata.size as u32).serialize())
                .index(Property::ReceivedAt, (metadata.received_at).serialize());
        } else {
            // Delete metadata
            batch
                .clear(Property::BodyStructure)
                .unindex(Property::Size, (metadata.size as u32).serialize())
                .unindex(Property::ReceivedAt, (metadata.received_at).serialize());
        }

        // Index properties
        let quota = if self.set {
            metadata.size as i64
        } else {
            -(metadata.size as i64)
        };
        batch.add(DirectoryClass::UsedQuota(account_id), quota);
        if let Some(tenant_id) = tenant_id {
            batch.add(DirectoryClass::UsedQuota(tenant_id), quota);
        }

        if metadata.has_attachments {
            if self.set {
                batch.tag(Property::HasAttachment, ());
            } else {
                batch.untag(Property::HasAttachment, ());
            }
        }

        // Index headers
        batch.index_headers(&metadata.contents.parts[0].headers, self.set);

        // Link blob
        if self.set {
            batch.set(
                BlobOp::Link {
                    hash: metadata.blob_hash.clone(),
                },
                Vec::new(),
            );
        } else {
            batch.clear(BlobOp::Link {
                hash: metadata.blob_hash.clone(),
            });
        }
        Ok(())
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

trait GetContentLanguage {
    fn language(&self) -> Option<Language>;
}

impl GetContentLanguage for MessagePart<'_> {
    fn language(&self) -> Option<Language> {
        self.headers
            .header_value(&HeaderName::ContentLanguage)
            .and_then(|v| {
                Language::from_iso_639(match v {
                    HeaderValue::Text(v) => v.as_ref(),
                    HeaderValue::TextList(v) => v.first()?,
                    _ => {
                        return None;
                    }
                })
                .unwrap_or(Language::Unknown)
                .into()
            })
    }
}

pub trait VisitValues<'x> {
    fn visit_addresses<'y: 'x>(&'y self, visitor: impl FnMut(AddressElement, &'x str));
    fn visit_text<'y: 'x>(&'y self, visitor: impl FnMut(&'x str));
    fn into_visit_text(self, visitor: impl FnMut(String));
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressElement {
    Name,
    Address,
    GroupName,
}

impl<'x> VisitValues<'x> for HeaderValue<'x> {
    fn visit_addresses<'y: 'x>(&'y self, mut visitor: impl FnMut(AddressElement, &'x str)) {
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

    fn visit_text<'y: 'x>(&'y self, mut visitor: impl FnMut(&'x str)) {
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

impl TrimTextValue for Cow<'_, str> {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            match self {
                Cow::Borrowed(v) => v.trim_text(length).into(),
                Cow::Owned(v) => v.trim_text(length).into(),
            }
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

impl TrimTextValue for String {
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
            result
        }
    }
}

impl<T: TrimTextValue> TrimTextValue for Vec<T> {
    fn trim_text(self, length: usize) -> Self {
        self.into_iter().map(|v| v.trim_text(length)).collect()
    }
}
