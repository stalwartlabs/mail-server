/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mailbox::{ArchivedUidMailbox, UidMailbox};
use common::storage::index::IndexableAndSerializableObject;
use jmap_proto::types::keyword::{ArchivedKeyword, Keyword};
use mail_parser::{
    ArchivedContentType, ArchivedEncoding, ArchivedHeaderName, ArchivedHeaderValue, DateTime,
    Encoding, Header, HeaderName, HeaderValue, PartType,
    core::rkyv::ArchivedGetHeader,
    decoders::{
        base64::base64_decode, charsets::map::charset_decoder,
        quoted_printable::quoted_printable_decode,
    },
};
use rkyv::{
    rend::{u16_le, u32_le},
    vec::ArchivedVec,
};
use std::{borrow::Cow, collections::VecDeque};
use utils::BlobHash;

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Default)]
pub struct MessageData {
    pub mailboxes: Vec<UidMailbox>,
    pub keywords: Vec<Keyword>,
    pub thread_id: u32,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadata {
    pub contents: Vec<MessageMetadataContents>,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub received_at: u64,
    pub preview: String,
    pub has_attachments: bool,
    pub raw_headers: Vec<u8>,
}

impl IndexableAndSerializableObject for MessageData {
    fn is_versioned() -> bool {
        true
    }
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadataContents {
    pub html_body: Vec<u16>,
    pub text_body: Vec<u16>,
    pub attachments: Vec<u16>,
    pub parts: Vec<MessageMetadataPart>,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageMetadataPart {
    pub headers: Vec<Header<'static>>,
    pub is_encoding_problem: bool,
    pub body: MetadataPartType,
    pub encoding: Encoding,
    pub size: u32,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub enum MetadataPartType {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(u16),
    Multipart(Vec<u16>),
}

impl MessageMetadataContents {
    pub fn root_part(&self) -> &MessageMetadataPart {
        &self.parts[0]
    }
}

#[derive(Debug)]
pub struct DecodedParts<'x> {
    pub raw_messages: Vec<Cow<'x, [u8]>>,
    pub parts: Vec<DecodedPart<'x>>,
}

#[derive(Debug)]
pub struct DecodedPart<'x> {
    pub message_id: usize,
    pub part_offset: usize,
    pub content: DecodedPartContent<'x>,
}

#[derive(Debug)]
pub enum DecodedPartContent<'x> {
    Text(Cow<'x, str>),
    Binary(Cow<'x, [u8]>),
}

impl<'x> DecodedParts<'x> {
    #[inline]
    pub fn raw_message(&self, message_id: usize) -> Option<&[u8]> {
        self.raw_messages.get(message_id).map(|m| m.as_ref())
    }

    #[inline]
    pub fn raw_message_section(&self, message_id: usize, from: usize, to: usize) -> Option<&[u8]> {
        self.raw_messages
            .get(message_id)
            .map(|m| m.as_ref())
            .and_then(|m| m.get(from..to))
    }

    #[inline]
    pub fn raw_message_section_arch(
        &self,
        message_id: usize,
        from: u32_le,
        to: u32_le,
    ) -> Option<&[u8]> {
        self.raw_message_section(message_id, u32::from(from) as usize, u32::from(to) as usize)
    }

    #[inline]
    pub fn part(&self, message_id: usize, part_offset: usize) -> Option<&DecodedPartContent<'x>> {
        self.parts
            .iter()
            .find(|p| p.message_id == message_id && p.part_offset == part_offset)
            .map(|p| &p.content)
    }

    #[inline]
    pub fn text_part(&self, message_id: usize, part_offset: usize) -> Option<&str> {
        self.part(message_id, part_offset).and_then(|p| match p {
            DecodedPartContent::Text(text) => Some(text.as_ref()),
            DecodedPartContent::Binary(_) => None,
        })
    }

    #[inline]
    pub fn binary_part(&self, message_id: usize, part_offset: usize) -> Option<&[u8]> {
        self.part(message_id, part_offset).map(|p| match p {
            DecodedPartContent::Text(part) => part.as_bytes(),
            DecodedPartContent::Binary(binary) => binary.as_ref(),
        })
    }
}

impl DecodedPartContent<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DecodedPartContent::Text(text) => text.as_bytes(),
            DecodedPartContent::Binary(binary) => binary,
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            DecodedPartContent::Text(text) => text.len(),
            DecodedPartContent::Binary(binary) => binary.len(),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            DecodedPartContent::Text(text) => text,
            DecodedPartContent::Binary(binary) => std::str::from_utf8(binary).unwrap_or_default(),
        }
    }
}

impl ArchivedMessageMetadata {
    #[inline(always)]
    pub fn message_id(&self, message_id: u16_le) -> &ArchivedMessageMetadataContents {
        &self.contents[u16::from(message_id) as usize]
    }

    pub fn decode_contents<'x>(&self, raw: &'x [u8]) -> DecodedParts<'x> {
        let mut result = DecodedParts {
            raw_messages: Vec::with_capacity(self.contents.len()),
            parts: Vec::new(),
        };

        for _ in 0..self.contents.len() {
            result.raw_messages.push(Cow::Borrowed(raw));
        }

        for (message_id, contents) in self.contents.iter().enumerate() {
            for part in contents.parts.iter() {
                let part_offset = u32::from(part.offset_header) as usize;
                match &part.body {
                    ArchivedMetadataPartType::Text
                    | ArchivedMetadataPartType::Html
                    | ArchivedMetadataPartType::Binary
                    | ArchivedMetadataPartType::InlineBinary => {
                        match result.raw_messages.get(message_id).unwrap() {
                            Cow::Borrowed(raw_message) => {
                                result.parts.push(DecodedPart {
                                    message_id,
                                    part_offset,
                                    content: part.decode_contents(raw_message),
                                });
                            }
                            Cow::Owned(raw_message) => {
                                result.parts.push(DecodedPart {
                                    message_id,
                                    part_offset,
                                    content: match part.decode_contents(raw_message) {
                                        DecodedPartContent::Text(text) => {
                                            DecodedPartContent::Text(text.into_owned().into())
                                        }
                                        DecodedPartContent::Binary(binary) => {
                                            DecodedPartContent::Binary(binary.into_owned().into())
                                        }
                                    },
                                });
                            }
                        }
                    }
                    ArchivedMetadataPartType::Message(nested_message_id) => {
                        let sub_contents = if !matches!(part.encoding, ArchivedEncoding::None) {
                            part.contents(result.raw_messages.get(message_id).unwrap())
                                .into_owned()
                        } else if let Some(Cow::Owned(raw_message)) =
                            result.raw_messages.get(message_id)
                        {
                            raw_message.clone()
                        } else {
                            continue;
                        };

                        result.raw_messages[usize::from(*nested_message_id)] = sub_contents.into();
                    }
                    _ => {}
                }
            }
        }

        result
    }
}

impl ArchivedMessageMetadataPart {
    pub fn contents<'x>(&self, raw_message: &'x [u8]) -> Cow<'x, [u8]> {
        let bytes = raw_message
            .get(u32::from(self.offset_body) as usize..u32::from(self.offset_end) as usize)
            .unwrap_or_default();
        match self.encoding {
            ArchivedEncoding::None => bytes.into(),
            ArchivedEncoding::QuotedPrintable => {
                quoted_printable_decode(bytes).unwrap_or_default().into()
            }
            ArchivedEncoding::Base64 => base64_decode(bytes).unwrap_or_default().into(),
        }
    }

    pub fn decode_contents<'x>(&self, raw_message: &'x [u8]) -> DecodedPartContent<'x> {
        let bytes = self.contents(raw_message);

        match self.body {
            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                DecodedPartContent::Text(
                    match (
                        bytes,
                        self.headers
                            .header_value(&ArchivedHeaderName::ContentType)
                            .and_then(|c| c.as_content_type())
                            .and_then(|ct| {
                                ct.attribute("charset")
                                    .and_then(|c| charset_decoder(c.as_bytes()))
                            }),
                    ) {
                        (Cow::Owned(vec), Some(charset_decoder)) => charset_decoder(&vec).into(),
                        (Cow::Owned(vec), None) => String::from_utf8(vec)
                            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
                            .into(),
                        (Cow::Borrowed(bytes), Some(charset_decoder)) => {
                            charset_decoder(bytes).into()
                        }
                        (Cow::Borrowed(bytes), None) => String::from_utf8_lossy(bytes),
                    },
                )
            }
            ArchivedMetadataPartType::Binary => DecodedPartContent::Binary(bytes),
            ArchivedMetadataPartType::InlineBinary => DecodedPartContent::Binary(bytes),
            ArchivedMetadataPartType::Message(_) | ArchivedMetadataPartType::Multipart(_) => {
                unreachable!()
            }
        }
    }
}

impl MessageMetadata {
    pub fn with_contents(mut self, message: mail_parser::Message<'_>) -> Self {
        let mut messages = VecDeque::from([message]);
        let mut message_id = 0;

        while let Some(message) = messages.pop_front() {
            let mut contents = MessageMetadataContents {
                html_body: message.html_body.into_iter().map(|c| c as u16).collect(),
                text_body: message.text_body.into_iter().map(|c| c as u16).collect(),
                attachments: message.attachments.into_iter().map(|c| c as u16).collect(),
                parts: Vec::with_capacity(message.parts.len()),
            };

            for part in message.parts {
                let (size, body) = match part.body {
                    PartType::Text(contents) => (contents.len(), MetadataPartType::Text),
                    PartType::Html(contents) => (contents.len(), MetadataPartType::Html),
                    PartType::Binary(contents) => (contents.len(), MetadataPartType::Binary),
                    PartType::InlineBinary(contents) => {
                        (contents.len(), MetadataPartType::InlineBinary)
                    }
                    PartType::Message(message) => {
                        let message_len = message.root_part().raw_len();
                        messages.push_back(message);
                        message_id += 1;

                        (message_len as usize, MetadataPartType::Message(message_id))
                    }
                    PartType::Multipart(parts) => (
                        0,
                        MetadataPartType::Multipart(parts.into_iter().map(|p| p as u16).collect()),
                    ),
                };

                contents.parts.push(MessageMetadataPart {
                    headers: part
                        .headers
                        .into_iter()
                        .map(|hdr| Header {
                            value: if matches!(
                                &hdr.name,
                                HeaderName::Subject
                                    | HeaderName::From
                                    | HeaderName::To
                                    | HeaderName::Cc
                                    | HeaderName::Date
                                    | HeaderName::Bcc
                                    | HeaderName::ReplyTo
                                    | HeaderName::Sender
                                    | HeaderName::Comments
                                    | HeaderName::InReplyTo
                                    | HeaderName::Keywords
                                    | HeaderName::MessageId
                                    | HeaderName::References
                                    | HeaderName::ResentMessageId
                                    | HeaderName::ContentDescription
                                    | HeaderName::ContentId
                                    | HeaderName::ContentLanguage
                                    | HeaderName::ContentLocation
                                    | HeaderName::ContentTransferEncoding
                                    | HeaderName::ContentType
                                    | HeaderName::ContentDisposition
                                    | HeaderName::ListId
                            ) {
                                hdr.value.into_owned()
                            } else {
                                HeaderValue::Empty
                            },
                            name: hdr.name.into_owned(),
                            offset_field: hdr.offset_field,
                            offset_start: hdr.offset_start,
                            offset_end: hdr.offset_end,
                        })
                        .collect(),
                    is_encoding_problem: part.is_encoding_problem,
                    encoding: part.encoding,
                    body,
                    size: size as u32,
                    offset_header: part.offset_header,
                    offset_body: part.offset_body,
                    offset_end: part.offset_end,
                });
            }
            self.contents.push(contents);
        }

        self
    }
}

impl ArchivedMessageMetadataPart {
    pub fn is_message(&self) -> bool {
        matches!(self.body, ArchivedMetadataPartType::Message(_))
    }

    pub fn sub_parts(&self) -> Option<&ArchivedVec<u16_le>> {
        if let ArchivedMetadataPartType::Multipart(parts) = &self.body {
            Some(parts)
        } else {
            None
        }
    }

    pub fn raw_len(&self) -> usize {
        (u32::from(self.offset_end)).saturating_sub(u32::from(self.offset_header)) as usize
    }

    pub fn header_values(
        &self,
        name: ArchivedHeaderName<'static>,
    ) -> impl Iterator<Item = &ArchivedHeaderValue<'static>> + Sync + Send {
        self.headers.iter().filter_map(move |header| {
            if header.name == name {
                Some(&header.value)
            } else {
                None
            }
        })
    }

    pub fn subject(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::Subject)
            .and_then(|header| header.as_text())
    }

    pub fn date(&self) -> Option<DateTime> {
        self.headers
            .header_value(&ArchivedHeaderName::Date)
            .and_then(|header| header.as_datetime())
            .map(|dt| dt.into())
    }

    pub fn message_id(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::MessageId)
            .and_then(|header| header.as_text())
    }

    pub fn in_reply_to(&self) -> &ArchivedHeaderValue<'static> {
        self.headers
            .header_value(&ArchivedHeaderName::InReplyTo)
            .unwrap_or(&ArchivedHeaderValue::Empty)
    }

    pub fn content_description(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentDescription)
            .and_then(|header| header.as_text())
    }

    pub fn content_disposition(&self) -> Option<&ArchivedContentType<'static>> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentDisposition)
            .and_then(|header| header.as_content_type())
    }

    pub fn content_id(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentId)
            .and_then(|header| header.as_text())
    }

    pub fn content_transfer_encoding(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentTransferEncoding)
            .and_then(|header| header.as_text())
    }

    pub fn content_type(&self) -> Option<&ArchivedContentType<'static>> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentType)
            .and_then(|header| header.as_content_type())
    }

    pub fn content_language(&self) -> &ArchivedHeaderValue<'static> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentLanguage)
            .unwrap_or(&ArchivedHeaderValue::Empty)
    }

    pub fn content_location(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentLocation)
            .and_then(|header| header.as_text())
    }

    pub fn attachment_name(&self) -> Option<&str> {
        self.content_disposition()
            .and_then(|cd| cd.attribute("filename"))
            .or_else(|| self.content_type().and_then(|ct| ct.attribute("name")))
    }
}

impl ArchivedMessageMetadataContents {
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.parts[0]
    }
}

impl MessageData {
    pub fn has_keyword(&self, keyword: &Keyword) -> bool {
        self.keywords.iter().any(|k| k == keyword)
    }

    pub fn set_keywords(&mut self, keywords: Vec<Keyword>) {
        self.keywords = keywords;
    }

    pub fn add_keyword(&mut self, keyword: Keyword) -> bool {
        if !self.keywords.contains(&keyword) {
            self.keywords.push(keyword);
            true
        } else {
            false
        }
    }

    pub fn remove_keyword(&mut self, keyword: &Keyword) -> bool {
        let prev_len = self.keywords.len();
        self.keywords.retain(|k| k != keyword);
        self.keywords.len() != prev_len
    }

    pub fn set_mailboxes(&mut self, mailboxes: Vec<UidMailbox>) {
        self.mailboxes = mailboxes;
    }

    pub fn add_mailbox(&mut self, mailbox: UidMailbox) {
        if !self.mailboxes.contains(&mailbox) {
            self.mailboxes.push(mailbox);
        }
    }

    pub fn remove_mailbox(&mut self, mailbox: u32) {
        self.mailboxes.retain(|m| m.mailbox_id != mailbox);
    }

    pub fn has_keyword_changes(&self, prev_data: &ArchivedMessageData) -> bool {
        self.keywords.len() != prev_data.keywords.len()
            || !self
                .keywords
                .iter()
                .all(|k| prev_data.keywords.iter().any(|pk| pk == k))
    }

    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
    }

    pub fn added_keywords(
        &self,
        prev_data: &ArchivedMessageData,
    ) -> impl Iterator<Item = &Keyword> {
        self.keywords
            .iter()
            .filter(|k| prev_data.keywords.iter().all(|pk| pk != *k))
    }

    pub fn removed_keywords<'x>(
        &'x self,
        prev_data: &'x ArchivedMessageData,
    ) -> impl Iterator<Item = &'x ArchivedKeyword> {
        prev_data
            .keywords
            .iter()
            .filter(|k| self.keywords.iter().all(|pk| pk != *k))
    }

    pub fn added_mailboxes(
        &self,
        prev_data: &ArchivedMessageData,
    ) -> impl Iterator<Item = &UidMailbox> {
        self.mailboxes.iter().filter(|m| {
            prev_data
                .mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn removed_mailboxes<'x>(
        &'x self,
        prev_data: &'x ArchivedMessageData,
    ) -> impl Iterator<Item = &'x ArchivedUidMailbox> {
        prev_data.mailboxes.iter().filter(|m| {
            self.mailboxes
                .iter()
                .all(|pm| pm.mailbox_id != m.mailbox_id)
        })
    }

    pub fn has_mailbox_changes(&self, prev_data: &ArchivedMessageData) -> bool {
        self.mailboxes.len() != prev_data.mailboxes.len()
            || !self.mailboxes.iter().all(|m| {
                prev_data
                    .mailboxes
                    .iter()
                    .any(|pm| pm.mailbox_id == m.mailbox_id)
            })
    }
}

impl ArchivedMessageData {
    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.mailboxes.iter().any(|m| m.mailbox_id == mailbox_id)
    }

    pub fn message_uid(&self, mailbox_id: u32) -> Option<u32> {
        self.mailboxes
            .iter()
            .find(|m| m.mailbox_id == mailbox_id)
            .map(|m| m.uid.to_native())
    }
}
