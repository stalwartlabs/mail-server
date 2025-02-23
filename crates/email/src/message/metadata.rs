/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use mail_parser::{
    decoders::{
        base64::base64_decode, charsets::map::charset_decoder,
        quoted_printable::quoted_printable_decode,
    },
    ContentType, Encoding, GetHeader, Header, HeaderName, HeaderValue, Message, MessagePart,
    MessagePartId, MimeHeaders, PartType,
};
use serde::{Deserialize, Serialize};
use utils::BlobHash;

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageMetadata<'x> {
    pub contents: MessageMetadataContents<'x>,
    pub blob_hash: BlobHash,
    pub size: usize,
    pub received_at: u64,
    pub preview: String,
    pub has_attachments: bool,
    pub raw_headers: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageMetadataContents<'x> {
    pub html_body: Vec<MessagePartId>,
    pub text_body: Vec<MessagePartId>,
    pub attachments: Vec<MessagePartId>,
    pub parts: Vec<MessageMetadataPart<'x>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageMetadataPart<'x> {
    pub headers: Vec<Header<'x>>,
    pub is_encoding_problem: bool,
    pub body: MetadataPartType<'x>,
    pub encoding: Encoding,
    pub size: usize,
    pub offset_header: usize,
    pub offset_body: usize,
    pub offset_end: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MetadataPartType<'x> {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(MessageMetadataContents<'x>),
    Multipart(Vec<MessagePartId>),
}

impl<'x> MessageMetadataContents<'x> {
    pub fn into_message(self, raw_message: &'x [u8]) -> Message<'x> {
        Message {
            html_body: self.html_body,
            text_body: self.text_body,
            attachments: self.attachments,
            parts: self
                .parts
                .into_iter()
                .map(|part| MessagePart {
                    body: match part.body {
                        MetadataPartType::Text
                        | MetadataPartType::Html
                        | MetadataPartType::Binary
                        | MetadataPartType::InlineBinary
                            if !raw_message.is_empty() =>
                        {
                            part.decode_contents(raw_message)
                        }
                        MetadataPartType::Message(_) if !raw_message.is_empty() => {
                            match part.contents(raw_message) {
                                Cow::Borrowed(_) => PartType::Message(
                                    part.body.unwrap_message().into_message(raw_message),
                                ),
                                Cow::Owned(raw_message) => PartType::Message(
                                    part.body
                                        .unwrap_message()
                                        .into_message(&raw_message)
                                        .into_owned(),
                                ),
                            }
                        }
                        MetadataPartType::Multipart(parts) => PartType::Multipart(parts),
                        _ => PartType::Binary(Cow::Borrowed(&[])),
                    },
                    headers: part.headers,
                    is_encoding_problem: part.is_encoding_problem,
                    encoding: part.encoding,
                    offset_header: part.offset_header,
                    offset_body: part.offset_body,
                    offset_end: part.offset_end,
                })
                .collect(),
            raw_message: raw_message.into(),
        }
    }

    pub fn root_part(&self) -> &MessageMetadataPart<'x> {
        &self.parts[0]
    }
}

impl<'x> MessageMetadataPart<'x> {
    pub fn contents<'y>(&self, raw_message: &'y [u8]) -> Cow<'y, [u8]> {
        let bytes = raw_message
            .get(self.offset_body..self.offset_end)
            .unwrap_or_default();
        match self.encoding {
            Encoding::None => bytes.into(),
            Encoding::QuotedPrintable => quoted_printable_decode(bytes).unwrap_or_default().into(),
            Encoding::Base64 => base64_decode(bytes).unwrap_or_default().into(),
        }
    }

    pub fn decode_contents<'y>(&self, raw_message: &'y [u8]) -> PartType<'y> {
        let bytes = self.contents(raw_message);

        match self.body {
            MetadataPartType::Text | MetadataPartType::Html => {
                let text = match (
                    bytes,
                    self.headers
                        .header_value(&HeaderName::ContentType)
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
                    (Cow::Borrowed(bytes), Some(charset_decoder)) => charset_decoder(bytes).into(),
                    (Cow::Borrowed(bytes), None) => String::from_utf8_lossy(bytes),
                };

                if matches!(self.body, MetadataPartType::Text) {
                    PartType::Text(text)
                } else {
                    PartType::Html(text)
                }
            }
            MetadataPartType::Binary => PartType::Binary(bytes),
            MetadataPartType::InlineBinary => PartType::InlineBinary(bytes),
            MetadataPartType::Message(_) | MetadataPartType::Multipart(_) => unreachable!(),
        }
    }

    pub fn remove_header(&mut self, header_name: &HeaderName) -> Option<HeaderValue<'x>> {
        for header in self.headers.iter_mut().rev() {
            if header.name == *header_name {
                return Some(std::mem::take(&mut header.value));
            }
        }
        None
    }
}

impl<'x> From<Message<'x>> for MessageMetadataContents<'x> {
    fn from(value: Message<'x>) -> Self {
        MessageMetadataContents {
            html_body: value.html_body,
            text_body: value.text_body,
            attachments: value.attachments,
            parts: value
                .parts
                .into_iter()
                .map(|part| {
                    let (size, body) = match part.body {
                        PartType::Text(contents) => (contents.len(), MetadataPartType::Text),
                        PartType::Html(contents) => (contents.len(), MetadataPartType::Html),
                        PartType::Binary(contents) => (contents.len(), MetadataPartType::Binary),
                        PartType::InlineBinary(contents) => {
                            (contents.len(), MetadataPartType::InlineBinary)
                        }
                        PartType::Message(message) => (
                            message.root_part().raw_len(),
                            MetadataPartType::Message(message.into()),
                        ),
                        PartType::Multipart(parts) => (0, MetadataPartType::Multipart(parts)),
                    };

                    MessageMetadataPart {
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
                                    hdr.value
                                } else {
                                    HeaderValue::Empty
                                },
                                name: hdr.name,
                                offset_field: hdr.offset_field,
                                offset_start: hdr.offset_start,
                                offset_end: hdr.offset_end,
                            })
                            .collect(),
                        is_encoding_problem: part.is_encoding_problem,
                        encoding: part.encoding,
                        body,
                        size,
                        offset_header: part.offset_header,
                        offset_body: part.offset_body,
                        offset_end: part.offset_end,
                    }
                })
                .collect(),
        }
    }
}

impl<'x> MetadataPartType<'x> {
    fn unwrap_message(self) -> MessageMetadataContents<'x> {
        match self {
            MetadataPartType::Message(message) => message,
            _ => panic!("unwrap_message called on non-message part"),
        }
    }
}

impl<'x> MimeHeaders<'x> for MessageMetadataPart<'x> {
    fn content_description(&self) -> Option<&str> {
        self.headers
            .header_value(&HeaderName::ContentDescription)
            .and_then(|header| header.as_text())
    }

    fn content_disposition(&self) -> Option<&ContentType> {
        self.headers
            .header_value(&HeaderName::ContentDisposition)
            .and_then(|header| header.as_content_type())
    }

    fn content_id(&self) -> Option<&str> {
        self.headers
            .header_value(&HeaderName::ContentId)
            .and_then(|header| header.as_text())
    }

    fn content_transfer_encoding(&self) -> Option<&str> {
        self.headers
            .header_value(&HeaderName::ContentTransferEncoding)
            .and_then(|header| header.as_text())
    }

    fn content_type(&self) -> Option<&ContentType> {
        self.headers
            .header_value(&HeaderName::ContentType)
            .and_then(|header| header.as_content_type())
    }

    fn content_language(&self) -> &HeaderValue {
        self.headers
            .header_value(&HeaderName::ContentLanguage)
            .unwrap_or(&HeaderValue::Empty)
    }

    fn content_location(&self) -> Option<&str> {
        self.headers
            .header_value(&HeaderName::ContentLocation)
            .and_then(|header| header.as_text())
    }
}
