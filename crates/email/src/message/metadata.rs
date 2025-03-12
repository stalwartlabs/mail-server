/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, collections::VecDeque, fmt::Display};

use common::storage::index::IndexableAndSerializableObject;
use jmap_proto::types::keyword::{ArchivedKeyword, Keyword};
use mail_parser::{
    PartType,
    decoders::{
        base64::base64_decode, charsets::map::charset_decoder,
        quoted_printable::quoted_printable_decode,
    },
};
use rkyv::{
    rend::{u16_le, u32_le},
    string::ArchivedString,
    vec::ArchivedVec,
};
use store::SerializedVersion;
use utils::BlobHash;

use crate::mailbox::{ArchivedUidMailbox, UidMailbox};

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct MessageData {
    pub mailboxes: Vec<UidMailbox>,
    pub keywords: Vec<Keyword>,
    pub change_id: u64,
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

impl IndexableAndSerializableObject for MessageData {}

impl SerializedVersion for MessageData {
    fn serialize_version() -> u8 {
        0
    }
}

impl SerializedVersion for MessageMetadata {
    fn serialize_version() -> u8 {
        0
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
    pub headers: Vec<Header>,
    pub is_encoding_problem: bool,
    pub body: MetadataPartType,
    pub encoding: Encoding,
    pub size: u32,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Default)]
pub enum Encoding {
    #[default]
    None = 0,
    QuotedPrintable = 1,
    Base64 = 2,
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

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub name: HeaderName,
    pub value: HeaderValue,
    pub offset_field: u32,
    pub offset_start: u32,
    pub offset_end: u32,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone)]
pub struct Addr {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone)]
pub struct Group {
    pub name: Option<String>,
    pub addresses: Vec<Addr>,
}

#[derive(
    rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone, PartialOrd, Ord,
)]
#[rkyv(derive(PartialEq, Debug))]
pub enum HeaderName {
    Subject,
    From,
    To,
    Cc,
    Date,
    Bcc,
    ReplyTo,
    Sender,
    Comments,
    InReplyTo,
    Keywords,
    Received,
    MessageId,
    References,
    ReturnPath,
    MimeVersion,
    ContentDescription,
    ContentId,
    ContentLanguage,
    ContentLocation,
    ContentTransferEncoding,
    ContentType,
    ContentDisposition,
    ResentTo,
    ResentFrom,
    ResentBcc,
    ResentCc,
    ResentSender,
    ResentDate,
    ResentMessageId,
    ListArchive,
    ListHelp,
    ListId,
    ListOwner,
    ListPost,
    ListSubscribe,
    ListUnsubscribe,
    Other(String),
    DkimSignature,
    ArcAuthenticationResults,
    ArcMessageSignature,
    ArcSeal,
}

#[derive(
    rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone, Default,
)]
pub enum HeaderValue {
    Address(Address),
    Text(String),
    TextList(Vec<String>),
    DateTime(CompactDateTime),
    ContentType(ContentType),
    #[default]
    Empty,
}

#[derive(
    rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone, Default,
)]
pub struct CompactDateTime(pub u64);

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone)]
pub enum Address {
    List(Vec<Addr>),
    Group(Vec<Group>),
}

#[derive(
    rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, PartialEq, Eq, Clone, Default,
)]
pub struct ContentType {
    pub c_type: String,
    pub c_subtype: Option<String>,
    pub attributes: Option<Vec<(String, String)>>,
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

                        (message_len, MetadataPartType::Message(message_id))
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
                                mail_parser::HeaderName::Subject
                                    | mail_parser::HeaderName::From
                                    | mail_parser::HeaderName::To
                                    | mail_parser::HeaderName::Cc
                                    | mail_parser::HeaderName::Date
                                    | mail_parser::HeaderName::Bcc
                                    | mail_parser::HeaderName::ReplyTo
                                    | mail_parser::HeaderName::Sender
                                    | mail_parser::HeaderName::Comments
                                    | mail_parser::HeaderName::InReplyTo
                                    | mail_parser::HeaderName::Keywords
                                    | mail_parser::HeaderName::MessageId
                                    | mail_parser::HeaderName::References
                                    | mail_parser::HeaderName::ResentMessageId
                                    | mail_parser::HeaderName::ContentDescription
                                    | mail_parser::HeaderName::ContentId
                                    | mail_parser::HeaderName::ContentLanguage
                                    | mail_parser::HeaderName::ContentLocation
                                    | mail_parser::HeaderName::ContentTransferEncoding
                                    | mail_parser::HeaderName::ContentType
                                    | mail_parser::HeaderName::ContentDisposition
                                    | mail_parser::HeaderName::ListId
                            ) {
                                hdr.value
                            } else {
                                mail_parser::HeaderValue::Empty
                            }
                            .into(),
                            name: hdr.name.into(),
                            offset_field: hdr.offset_field as u32,
                            offset_start: hdr.offset_start as u32,
                            offset_end: hdr.offset_end as u32,
                        })
                        .collect(),
                    is_encoding_problem: part.is_encoding_problem,
                    encoding: part.encoding.into(),
                    body,
                    size: size as u32,
                    offset_header: part.offset_header as u32,
                    offset_body: part.offset_body as u32,
                    offset_end: part.offset_end as u32,
                });
            }
            self.contents.push(contents);
        }

        self
    }
}

impl From<mail_parser::Encoding> for Encoding {
    fn from(value: mail_parser::Encoding) -> Self {
        match value {
            mail_parser::Encoding::None => Encoding::None,
            mail_parser::Encoding::QuotedPrintable => Encoding::QuotedPrintable,
            mail_parser::Encoding::Base64 => Encoding::Base64,
        }
    }
}

impl From<mail_parser::HeaderName<'_>> for HeaderName {
    fn from(value: mail_parser::HeaderName<'_>) -> Self {
        match value {
            mail_parser::HeaderName::Subject => HeaderName::Subject,
            mail_parser::HeaderName::From => HeaderName::From,
            mail_parser::HeaderName::To => HeaderName::To,
            mail_parser::HeaderName::Cc => HeaderName::Cc,
            mail_parser::HeaderName::Date => HeaderName::Date,
            mail_parser::HeaderName::Bcc => HeaderName::Bcc,
            mail_parser::HeaderName::ReplyTo => HeaderName::ReplyTo,
            mail_parser::HeaderName::Sender => HeaderName::Sender,
            mail_parser::HeaderName::Comments => HeaderName::Comments,
            mail_parser::HeaderName::InReplyTo => HeaderName::InReplyTo,
            mail_parser::HeaderName::Keywords => HeaderName::Keywords,
            mail_parser::HeaderName::Received => HeaderName::Received,
            mail_parser::HeaderName::MessageId => HeaderName::MessageId,
            mail_parser::HeaderName::References => HeaderName::References,
            mail_parser::HeaderName::ReturnPath => HeaderName::ReturnPath,
            mail_parser::HeaderName::MimeVersion => HeaderName::MimeVersion,
            mail_parser::HeaderName::ContentDescription => HeaderName::ContentDescription,
            mail_parser::HeaderName::ContentId => HeaderName::ContentId,
            mail_parser::HeaderName::ContentLanguage => HeaderName::ContentLanguage,
            mail_parser::HeaderName::ContentLocation => HeaderName::ContentLocation,
            mail_parser::HeaderName::ContentTransferEncoding => HeaderName::ContentTransferEncoding,
            mail_parser::HeaderName::ContentType => HeaderName::ContentType,
            mail_parser::HeaderName::ContentDisposition => HeaderName::ContentDisposition,
            mail_parser::HeaderName::ResentTo => HeaderName::ResentTo,
            mail_parser::HeaderName::ResentFrom => HeaderName::ResentFrom,
            mail_parser::HeaderName::ResentBcc => HeaderName::ResentBcc,
            mail_parser::HeaderName::ResentCc => HeaderName::ResentCc,
            mail_parser::HeaderName::ResentSender => HeaderName::ResentSender,
            mail_parser::HeaderName::ResentDate => HeaderName::ResentDate,
            mail_parser::HeaderName::ResentMessageId => HeaderName::ResentMessageId,
            mail_parser::HeaderName::ListArchive => HeaderName::ListArchive,
            mail_parser::HeaderName::ListHelp => HeaderName::ListHelp,
            mail_parser::HeaderName::ListId => HeaderName::ListId,
            mail_parser::HeaderName::ListOwner => HeaderName::ListOwner,
            mail_parser::HeaderName::ListPost => HeaderName::ListPost,
            mail_parser::HeaderName::ListSubscribe => HeaderName::ListSubscribe,
            mail_parser::HeaderName::ListUnsubscribe => HeaderName::ListUnsubscribe,
            mail_parser::HeaderName::Other(other) => HeaderName::Other(other.into_owned()),
            mail_parser::HeaderName::DkimSignature => HeaderName::DkimSignature,
            mail_parser::HeaderName::ArcAuthenticationResults => {
                HeaderName::ArcAuthenticationResults
            }
            mail_parser::HeaderName::ArcMessageSignature => HeaderName::ArcMessageSignature,
            mail_parser::HeaderName::ArcSeal => HeaderName::ArcSeal,
            _ => unreachable!(),
        }
    }
}

impl From<mail_parser::HeaderValue<'_>> for HeaderValue {
    fn from(value: mail_parser::HeaderValue) -> Self {
        match value {
            mail_parser::HeaderValue::Address(address) => HeaderValue::Address(address.into()),
            mail_parser::HeaderValue::Text(cow) => HeaderValue::Text(cow.into_owned()),
            mail_parser::HeaderValue::TextList(cows) => {
                HeaderValue::TextList(cows.into_iter().map(|cow| cow.into_owned()).collect())
            }
            mail_parser::HeaderValue::DateTime(date_time) => {
                HeaderValue::DateTime(date_time.into())
            }
            mail_parser::HeaderValue::ContentType(content_type) => {
                HeaderValue::ContentType(content_type.into())
            }
            mail_parser::HeaderValue::Received(_) | mail_parser::HeaderValue::Empty => {
                HeaderValue::Empty
            }
        }
    }
}

impl From<mail_parser::ContentType<'_>> for ContentType {
    fn from(value: mail_parser::ContentType<'_>) -> Self {
        ContentType {
            c_type: value.c_type.into_owned(),
            c_subtype: value.c_subtype.map(|cow| cow.into_owned()),
            attributes: value.attributes.map(|attrs| {
                attrs
                    .into_iter()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect()
            }),
        }
    }
}

impl From<mail_parser::Address<'_>> for Address {
    fn from(value: mail_parser::Address<'_>) -> Self {
        match value {
            mail_parser::Address::List(addrs) => {
                Address::List(addrs.into_iter().map(|addr| addr.into()).collect())
            }
            mail_parser::Address::Group(groups) => {
                Address::Group(groups.into_iter().map(|group| group.into()).collect())
            }
        }
    }
}

impl From<mail_parser::Addr<'_>> for Addr {
    fn from(value: mail_parser::Addr<'_>) -> Self {
        Addr {
            name: value.name.map(|cow| cow.into_owned()),
            address: value.address.map(|cow| cow.into_owned()),
        }
    }
}

impl From<mail_parser::Group<'_>> for Group {
    fn from(value: mail_parser::Group<'_>) -> Self {
        Group {
            name: value.name.map(|cow| cow.into_owned()),
            addresses: value
                .addresses
                .into_iter()
                .map(|addr| addr.into())
                .collect(),
        }
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
        name: ArchivedHeaderName,
    ) -> impl Iterator<Item = &ArchivedHeaderValue> + Sync + Send {
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

    pub fn date(&self) -> Option<mail_parser::DateTime> {
        self.headers
            .header_value(&ArchivedHeaderName::Date)
            .and_then(|header| header.as_datetime())
    }

    pub fn message_id(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::MessageId)
            .and_then(|header| header.as_text())
    }

    pub fn in_reply_to(&self) -> &ArchivedHeaderValue {
        self.headers
            .header_value(&ArchivedHeaderName::InReplyTo)
            .unwrap_or(&ArchivedHeaderValue::Empty)
    }

    pub fn content_description(&self) -> Option<&str> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentDescription)
            .and_then(|header| header.as_text())
    }

    pub fn content_disposition(&self) -> Option<&ArchivedContentType> {
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

    pub fn content_type(&self) -> Option<&ArchivedContentType> {
        self.headers
            .header_value(&ArchivedHeaderName::ContentType)
            .and_then(|header| header.as_content_type())
    }

    pub fn content_language(&self) -> &ArchivedHeaderValue {
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

pub trait GetHeader {
    fn header_value(&self, name: &HeaderName) -> Option<&HeaderValue>;
    fn header(&self, name: impl Into<HeaderName>) -> Option<&Header>;
}

impl GetHeader for Vec<Header> {
    fn header_value(&self, name: &HeaderName) -> Option<&HeaderValue> {
        self.iter()
            .rev()
            .find(|header| &header.name == name)
            .map(|header| &header.value)
    }

    fn header(&self, name: impl Into<HeaderName>) -> Option<&Header> {
        let name = name.into();
        self.iter().rev().find(|header| header.name == name)
    }
}

pub trait ArchivedGetHeader {
    fn header_value(&self, name: &ArchivedHeaderName) -> Option<&ArchivedHeaderValue>;
    fn header(&self, name: impl Into<ArchivedHeaderName>) -> Option<&ArchivedHeader>;
    fn convert_header(
        &self,
        header_name: &ArchivedHeaderName,
    ) -> Option<mail_parser::HeaderValue<'static>>;
}

impl ArchivedGetHeader for ArchivedVec<ArchivedHeader> {
    fn header_value(&self, name: &ArchivedHeaderName) -> Option<&ArchivedHeaderValue> {
        self.iter()
            .rev()
            .find(|header| &header.name == name)
            .map(|header| &header.value)
    }

    fn header(&self, name: impl Into<ArchivedHeaderName>) -> Option<&ArchivedHeader> {
        let name = name.into();
        self.iter().rev().find(|header| header.name == name)
    }

    fn convert_header(
        &self,
        header_name: &ArchivedHeaderName,
    ) -> Option<mail_parser::HeaderValue<'static>> {
        for header in self.iter().rev() {
            if header.name == *header_name {
                return Some(mail_parser::HeaderValue::from(&header.value));
            }
        }
        None
    }
}

impl HeaderValue {
    pub fn as_text(&self) -> Option<&str> {
        match *self {
            HeaderValue::Text(ref s) => Some(s),
            HeaderValue::TextList(ref l) => l.last().map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn as_content_type(&self) -> Option<&ContentType> {
        match *self {
            HeaderValue::ContentType(ref c) => Some(c),
            _ => None,
        }
    }
}

impl ArchivedHeaderValue {
    pub fn as_text(&self) -> Option<&str> {
        match *self {
            ArchivedHeaderValue::Text(ref s) => Some(s),
            ArchivedHeaderValue::TextList(ref l) => l.last().map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn as_content_type(&self) -> Option<&ArchivedContentType> {
        match *self {
            ArchivedHeaderValue::ContentType(ref c) => Some(c),
            _ => None,
        }
    }

    pub fn as_text_list(&self) -> Option<&[ArchivedString]> {
        match *self {
            ArchivedHeaderValue::Text(ref s) => Some(std::slice::from_ref(s)),
            ArchivedHeaderValue::TextList(ref l) => Some(l.as_slice()),
            _ => None,
        }
    }

    pub fn as_datetime(&self) -> Option<mail_parser::DateTime> {
        match self {
            ArchivedHeaderValue::DateTime(d) => Some(d.into()),
            _ => None,
        }
    }
}

impl HeaderName {
    pub fn id(&self) -> u8 {
        match self {
            HeaderName::Subject => 0,
            HeaderName::From => 1,
            HeaderName::To => 2,
            HeaderName::Cc => 3,
            HeaderName::Date => 4,
            HeaderName::Bcc => 5,
            HeaderName::ReplyTo => 6,
            HeaderName::Sender => 7,
            HeaderName::Comments => 8,
            HeaderName::InReplyTo => 9,
            HeaderName::Keywords => 10,
            HeaderName::Received => 11,
            HeaderName::MessageId => 12,
            HeaderName::References => 13,
            HeaderName::ReturnPath => 14,
            HeaderName::MimeVersion => 15,
            HeaderName::ContentDescription => 16,
            HeaderName::ContentId => 17,
            HeaderName::ContentLanguage => 18,
            HeaderName::ContentLocation => 19,
            HeaderName::ContentTransferEncoding => 20,
            HeaderName::ContentType => 21,
            HeaderName::ContentDisposition => 22,
            HeaderName::ResentTo => 23,
            HeaderName::ResentFrom => 24,
            HeaderName::ResentBcc => 25,
            HeaderName::ResentCc => 26,
            HeaderName::ResentSender => 27,
            HeaderName::ResentDate => 28,
            HeaderName::ResentMessageId => 29,
            HeaderName::ListArchive => 30,
            HeaderName::ListHelp => 31,
            HeaderName::ListId => 32,
            HeaderName::ListOwner => 33,
            HeaderName::ListPost => 34,
            HeaderName::ListSubscribe => 35,
            HeaderName::ListUnsubscribe => 36,
            HeaderName::Other(_) => 37,
            HeaderName::ArcAuthenticationResults => 38,
            HeaderName::ArcMessageSignature => 39,
            HeaderName::ArcSeal => 40,
            HeaderName::DkimSignature => 41,
        }
    }
}

impl ArchivedHeaderName {
    pub fn id(&self) -> u8 {
        match self {
            ArchivedHeaderName::Subject => 0,
            ArchivedHeaderName::From => 1,
            ArchivedHeaderName::To => 2,
            ArchivedHeaderName::Cc => 3,
            ArchivedHeaderName::Date => 4,
            ArchivedHeaderName::Bcc => 5,
            ArchivedHeaderName::ReplyTo => 6,
            ArchivedHeaderName::Sender => 7,
            ArchivedHeaderName::Comments => 8,
            ArchivedHeaderName::InReplyTo => 9,
            ArchivedHeaderName::Keywords => 10,
            ArchivedHeaderName::Received => 11,
            ArchivedHeaderName::MessageId => 12,
            ArchivedHeaderName::References => 13,
            ArchivedHeaderName::ReturnPath => 14,
            ArchivedHeaderName::MimeVersion => 15,
            ArchivedHeaderName::ContentDescription => 16,
            ArchivedHeaderName::ContentId => 17,
            ArchivedHeaderName::ContentLanguage => 18,
            ArchivedHeaderName::ContentLocation => 19,
            ArchivedHeaderName::ContentTransferEncoding => 20,
            ArchivedHeaderName::ContentType => 21,
            ArchivedHeaderName::ContentDisposition => 22,
            ArchivedHeaderName::ResentTo => 23,
            ArchivedHeaderName::ResentFrom => 24,
            ArchivedHeaderName::ResentBcc => 25,
            ArchivedHeaderName::ResentCc => 26,
            ArchivedHeaderName::ResentSender => 27,
            ArchivedHeaderName::ResentDate => 28,
            ArchivedHeaderName::ResentMessageId => 29,
            ArchivedHeaderName::ListArchive => 30,
            ArchivedHeaderName::ListHelp => 31,
            ArchivedHeaderName::ListId => 32,
            ArchivedHeaderName::ListOwner => 33,
            ArchivedHeaderName::ListPost => 34,
            ArchivedHeaderName::ListSubscribe => 35,
            ArchivedHeaderName::ListUnsubscribe => 36,
            ArchivedHeaderName::Other(_) => 37,
            ArchivedHeaderName::ArcAuthenticationResults => 38,
            ArchivedHeaderName::ArcMessageSignature => 39,
            ArchivedHeaderName::ArcSeal => 40,
            ArchivedHeaderName::DkimSignature => 41,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ArchivedHeaderName::Subject => "Subject",
            ArchivedHeaderName::From => "From",
            ArchivedHeaderName::To => "To",
            ArchivedHeaderName::Cc => "Cc",
            ArchivedHeaderName::Date => "Date",
            ArchivedHeaderName::Bcc => "Bcc",
            ArchivedHeaderName::ReplyTo => "Reply-To",
            ArchivedHeaderName::Sender => "Sender",
            ArchivedHeaderName::Comments => "Comments",
            ArchivedHeaderName::InReplyTo => "In-Reply-To",
            ArchivedHeaderName::Keywords => "Keywords",
            ArchivedHeaderName::Received => "Received",
            ArchivedHeaderName::MessageId => "Message-ID",
            ArchivedHeaderName::References => "References",
            ArchivedHeaderName::ReturnPath => "Return-Path",
            ArchivedHeaderName::MimeVersion => "MIME-Version",
            ArchivedHeaderName::ContentDescription => "Content-Description",
            ArchivedHeaderName::ContentId => "Content-ID",
            ArchivedHeaderName::ContentLanguage => "Content-Language",
            ArchivedHeaderName::ContentLocation => "Content-Location",
            ArchivedHeaderName::ContentTransferEncoding => "Content-Transfer-Encoding",
            ArchivedHeaderName::ContentType => "Content-Type",
            ArchivedHeaderName::ContentDisposition => "Content-Disposition",
            ArchivedHeaderName::ResentTo => "Resent-To",
            ArchivedHeaderName::ResentFrom => "Resent-From",
            ArchivedHeaderName::ResentBcc => "Resent-Bcc",
            ArchivedHeaderName::ResentCc => "Resent-Cc",
            ArchivedHeaderName::ResentSender => "Resent-Sender",
            ArchivedHeaderName::ResentDate => "Resent-Date",
            ArchivedHeaderName::ResentMessageId => "Resent-Message-ID",
            ArchivedHeaderName::ListArchive => "List-Archive",
            ArchivedHeaderName::ListHelp => "List-Help",
            ArchivedHeaderName::ListId => "List-ID",
            ArchivedHeaderName::ListOwner => "List-Owner",
            ArchivedHeaderName::ListPost => "List-Post",
            ArchivedHeaderName::ListSubscribe => "List-Subscribe",
            ArchivedHeaderName::ListUnsubscribe => "List-Unsubscribe",
            ArchivedHeaderName::ArcAuthenticationResults => "ARC-Authentication-Results",
            ArchivedHeaderName::ArcMessageSignature => "ARC-Message-Signature",
            ArchivedHeaderName::ArcSeal => "ARC-Seal",
            ArchivedHeaderName::DkimSignature => "DKIM-Signature",
            ArchivedHeaderName::Other(v) => v.as_str(),
        }
    }

    pub fn is_mime_header(&self) -> bool {
        matches!(
            self,
            ArchivedHeaderName::ContentDescription
                | ArchivedHeaderName::ContentId
                | ArchivedHeaderName::ContentLanguage
                | ArchivedHeaderName::ContentLocation
                | ArchivedHeaderName::ContentTransferEncoding
                | ArchivedHeaderName::ContentType
                | ArchivedHeaderName::ContentDisposition
        )
    }
}

impl Display for ArchivedHeaderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ArchivedContentType {
    pub fn ctype(&self) -> &str {
        &self.c_type
    }

    pub fn subtype(&self) -> Option<&str> {
        self.c_subtype.as_deref()
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .as_ref()?
            .iter()
            .find(|k| k.0 == name)?
            .1
            .as_ref()
            .into()
    }
}

impl ArchivedMessageMetadataContents {
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.parts[0]
    }
}

impl ArchivedAddress {
    pub fn iter(&self) -> Box<dyn DoubleEndedIterator<Item = &ArchivedAddr> + '_ + Sync + Send> {
        match self {
            ArchivedAddress::List(list) => Box::new(list.iter()),
            ArchivedAddress::Group(group) => {
                Box::new(group.iter().flat_map(|group| group.addresses.iter()))
            }
        }
    }
}

impl ArchivedAddr {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

impl From<&ArchivedHeaderName> for mail_parser::HeaderName<'static> {
    fn from(value: &ArchivedHeaderName) -> Self {
        match value {
            ArchivedHeaderName::Subject => mail_parser::HeaderName::Subject,
            ArchivedHeaderName::From => mail_parser::HeaderName::From,
            ArchivedHeaderName::To => mail_parser::HeaderName::To,
            ArchivedHeaderName::Cc => mail_parser::HeaderName::Cc,
            ArchivedHeaderName::Date => mail_parser::HeaderName::Date,
            ArchivedHeaderName::Bcc => mail_parser::HeaderName::Bcc,
            ArchivedHeaderName::ReplyTo => mail_parser::HeaderName::ReplyTo,
            ArchivedHeaderName::Sender => mail_parser::HeaderName::Sender,
            ArchivedHeaderName::Comments => mail_parser::HeaderName::Comments,
            ArchivedHeaderName::InReplyTo => mail_parser::HeaderName::InReplyTo,
            ArchivedHeaderName::Keywords => mail_parser::HeaderName::Keywords,
            ArchivedHeaderName::Received => mail_parser::HeaderName::Received,
            ArchivedHeaderName::MessageId => mail_parser::HeaderName::MessageId,
            ArchivedHeaderName::References => mail_parser::HeaderName::References,
            ArchivedHeaderName::ReturnPath => mail_parser::HeaderName::ReturnPath,
            ArchivedHeaderName::MimeVersion => mail_parser::HeaderName::MimeVersion,
            ArchivedHeaderName::ContentDescription => mail_parser::HeaderName::ContentDescription,
            ArchivedHeaderName::ContentId => mail_parser::HeaderName::ContentId,
            ArchivedHeaderName::ContentLanguage => mail_parser::HeaderName::ContentLanguage,
            ArchivedHeaderName::ContentLocation => mail_parser::HeaderName::ContentLocation,
            ArchivedHeaderName::ContentTransferEncoding => {
                mail_parser::HeaderName::ContentTransferEncoding
            }
            ArchivedHeaderName::ContentType => mail_parser::HeaderName::ContentType,
            ArchivedHeaderName::ContentDisposition => mail_parser::HeaderName::ContentDisposition,
            ArchivedHeaderName::ResentTo => mail_parser::HeaderName::ResentTo,
            ArchivedHeaderName::ResentFrom => mail_parser::HeaderName::ResentFrom,
            ArchivedHeaderName::ResentBcc => mail_parser::HeaderName::ResentBcc,
            ArchivedHeaderName::ResentCc => mail_parser::HeaderName::ResentCc,
            ArchivedHeaderName::ResentSender => mail_parser::HeaderName::ResentSender,
            ArchivedHeaderName::ResentDate => mail_parser::HeaderName::ResentDate,
            ArchivedHeaderName::ResentMessageId => mail_parser::HeaderName::ResentMessageId,
            ArchivedHeaderName::ListArchive => mail_parser::HeaderName::ListArchive,
            ArchivedHeaderName::ListHelp => mail_parser::HeaderName::ListHelp,
            ArchivedHeaderName::ListId => mail_parser::HeaderName::ListId,
            ArchivedHeaderName::ListOwner => mail_parser::HeaderName::ListOwner,
            ArchivedHeaderName::ListPost => mail_parser::HeaderName::ListPost,
            ArchivedHeaderName::ListSubscribe => mail_parser::HeaderName::ListSubscribe,
            ArchivedHeaderName::ListUnsubscribe => mail_parser::HeaderName::ListUnsubscribe,
            ArchivedHeaderName::Other(other) => {
                mail_parser::HeaderName::Other(other.to_string().into())
            }
            ArchivedHeaderName::ArcAuthenticationResults => {
                mail_parser::HeaderName::ArcAuthenticationResults
            }
            ArchivedHeaderName::ArcMessageSignature => mail_parser::HeaderName::ArcMessageSignature,
            ArchivedHeaderName::ArcSeal => mail_parser::HeaderName::ArcSeal,
            ArchivedHeaderName::DkimSignature => mail_parser::HeaderName::DkimSignature,
        }
    }
}

impl From<&ArchivedHeaderValue> for mail_parser::HeaderValue<'static> {
    fn from(value: &ArchivedHeaderValue) -> Self {
        match value {
            ArchivedHeaderValue::Text(s) => mail_parser::HeaderValue::Text(s.to_string().into()),
            ArchivedHeaderValue::TextList(list) => mail_parser::HeaderValue::TextList(
                list.iter().map(|s| s.to_string().into()).collect(),
            ),
            ArchivedHeaderValue::DateTime(d) => mail_parser::HeaderValue::DateTime(d.into()),
            ArchivedHeaderValue::ContentType(ct) => {
                mail_parser::HeaderValue::ContentType(ct.into())
            }
            ArchivedHeaderValue::Empty => mail_parser::HeaderValue::Empty,
            ArchivedHeaderValue::Address(a) => mail_parser::HeaderValue::Address(a.into()),
        }
    }
}

impl From<&ArchivedAddress> for mail_parser::Address<'static> {
    fn from(value: &ArchivedAddress) -> Self {
        match value {
            ArchivedAddress::List(list) => {
                mail_parser::Address::List(list.iter().map(Into::into).collect())
            }
            ArchivedAddress::Group(groups) => {
                mail_parser::Address::Group(groups.iter().map(Into::into).collect())
            }
        }
    }
}

impl From<&ArchivedContentType> for mail_parser::ContentType<'static> {
    fn from(value: &ArchivedContentType) -> Self {
        mail_parser::ContentType {
            c_type: value.c_type.to_string().into(),
            c_subtype: value.subtype().map(|s| s.to_string().into()),
            attributes: value.attributes.as_ref().map(|attrs| {
                attrs
                    .iter()
                    .map(|a| (a.0.to_string().into(), a.0.to_string().into()))
                    .collect()
            }),
        }
    }
}

impl From<&ArchivedGroup> for mail_parser::Group<'static> {
    fn from(value: &ArchivedGroup) -> Self {
        mail_parser::Group {
            name: value.name.as_ref().map(|s| s.to_string().into()),
            addresses: value.addresses.iter().map(|a| a.into()).collect(),
        }
    }
}

impl From<&ArchivedAddr> for mail_parser::Addr<'static> {
    fn from(value: &ArchivedAddr) -> Self {
        mail_parser::Addr {
            name: value.name().map(|s| s.to_string().into()),
            address: value.address().map(|s| s.to_string().into()),
        }
    }
}

impl Encoding {
    pub fn id(&self) -> u8 {
        match self {
            Encoding::None => 0,
            Encoding::QuotedPrintable => 1,
            Encoding::Base64 => 2,
        }
    }
}

impl ArchivedEncoding {
    pub fn id(&self) -> u8 {
        match self {
            ArchivedEncoding::None => 0,
            ArchivedEncoding::QuotedPrintable => 1,
            ArchivedEncoding::Base64 => 2,
        }
    }
}

impl From<mail_parser::DateTime> for CompactDateTime {
    fn from(dt: mail_parser::DateTime) -> Self {
        let mut value: u64 = 0;
        value |= (dt.year as u64) << 48;
        value |= (dt.month as u64) << 44;
        value |= (dt.day as u64) << 39;
        value |= (dt.hour as u64) << 34;
        value |= (dt.minute as u64) << 28;
        value |= (dt.second as u64) << 22;
        value |= (if dt.tz_before_gmt { 1 } else { 0 }) << 21;
        value |= (dt.tz_hour as u64) << 16;
        value |= (dt.tz_minute as u64) << 10;

        CompactDateTime(value)
    }
}

impl From<&ArchivedCompactDateTime> for mail_parser::DateTime {
    fn from(value: &ArchivedCompactDateTime) -> Self {
        let value = u64::from(value.0);
        mail_parser::DateTime {
            year: (value >> 48) as u16,
            month: ((value >> 44) & 0xF) as u8,
            day: ((value >> 39) & 0x1F) as u8,
            hour: ((value >> 34) & 0x1F) as u8,
            minute: ((value >> 28) & 0x3F) as u8,
            second: ((value >> 22) & 0x3F) as u8,
            tz_before_gmt: ((value >> 21) & 0x1) == 1,
            tz_hour: ((value >> 16) & 0x1F) as u8,
            tz_minute: ((value >> 10) & 0x3F) as u8,
        }
    }
}

impl From<&CompactDateTime> for mail_parser::DateTime {
    fn from(value: &CompactDateTime) -> Self {
        let value = value.0;
        mail_parser::DateTime {
            year: (value >> 48) as u16,
            month: ((value >> 44) & 0xF) as u8,
            day: ((value >> 39) & 0x1F) as u8,
            hour: ((value >> 34) & 0x1F) as u8,
            minute: ((value >> 28) & 0x3F) as u8,
            second: ((value >> 22) & 0x3F) as u8,
            tz_before_gmt: ((value >> 21) & 0x1) == 1,
            tz_hour: ((value >> 16) & 0x1F) as u8,
            tz_minute: ((value >> 10) & 0x3F) as u8,
        }
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
}
