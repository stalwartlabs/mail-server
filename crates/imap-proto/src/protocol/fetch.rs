/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use mail_parser::DateTime;

use super::{
    literal_string, quoted_or_literal_string, quoted_or_literal_string_or_nil,
    quoted_rfc2822_or_nil, quoted_timestamp, Flag, ImapResponse, Sequence,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub sequence_set: Sequence,
    pub attributes: Vec<Attribute>,
    pub changed_since: Option<u64>,
    pub include_vanished: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'x> {
    pub is_uid: bool,
    pub items: Vec<FetchItem<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchItem<'x> {
    pub id: u32,
    pub items: Vec<DataItem<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    Envelope,
    Flags,
    InternalDate,
    Rfc822,
    Rfc822Size,
    Rfc822Header,
    Rfc822Text,
    Body,
    BodyStructure,
    BodySection {
        peek: bool,
        sections: Vec<Section>,
        partial: Option<(u32, u32)>,
    },
    Uid,
    Binary {
        peek: bool,
        sections: Vec<u32>,
        partial: Option<(u32, u32)>,
    },
    BinarySize {
        sections: Vec<u32>,
    },
    Preview {
        lazy: bool,
    },
    ModSeq,
    EmailId,
    ThreadId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    Part { num: u32 },
    Header,
    HeaderFields { not: bool, fields: Vec<String> },
    Text,
    Mime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataItem<'x> {
    Binary {
        sections: Vec<u32>,
        offset: Option<u32>,
        contents: BodyContents<'x>,
    },
    BinarySize {
        sections: Vec<u32>,
        size: usize,
    },
    Body {
        part: BodyPart<'x>,
    },
    BodyStructure {
        part: BodyPart<'x>,
    },
    BodySection {
        sections: Vec<Section>,
        origin_octet: Option<u32>,
        contents: Cow<'x, [u8]>,
    },
    Envelope {
        envelope: Envelope<'x>,
    },
    Flags {
        flags: Vec<Flag>,
    },
    InternalDate {
        date: i64,
    },
    Uid {
        uid: u32,
    },
    Rfc822 {
        contents: Cow<'x, [u8]>,
    },
    Rfc822Header {
        contents: Cow<'x, [u8]>,
    },
    Rfc822Size {
        size: usize,
    },
    Rfc822Text {
        contents: Cow<'x, [u8]>,
    },
    Preview {
        contents: Option<Cow<'x, [u8]>>,
    },
    ModSeq {
        modseq: u64,
    },
    EmailId {
        email_id: String,
    },
    ThreadId {
        thread_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address<'x> {
    Single(EmailAddress<'x>),
    Group(AddressGroup<'x>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressGroup<'x> {
    pub name: Option<Cow<'x, str>>,
    pub addresses: Vec<EmailAddress<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress<'x> {
    pub name: Option<Cow<'x, str>>,
    pub address: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyContents<'x> {
    Text(Cow<'x, str>),
    Bytes(Cow<'x, [u8]>),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Envelope<'x> {
    pub date: Option<DateTime>,
    pub subject: Option<Cow<'x, str>>,
    pub from: Vec<Address<'x>>,
    pub sender: Vec<Address<'x>>,
    pub reply_to: Vec<Address<'x>>,
    pub to: Vec<Address<'x>>,
    pub cc: Vec<Address<'x>>,
    pub bcc: Vec<Address<'x>>,
    pub in_reply_to: Option<Cow<'x, str>>,
    pub message_id: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::type_complexity)]
pub enum BodyPart<'x> {
    Multipart {
        body_parts: Vec<BodyPart<'x>>,
        body_subtype: Cow<'x, str>,
        // Extension data
        body_parameters: Option<Vec<(Cow<'x, str>, Cow<'x, str>)>>,
        extension: BodyPartExtension<'x>,
    },
    Basic {
        body_type: Option<Cow<'x, str>>,
        fields: BodyPartFields<'x>,
        // Extension data
        body_md5: Option<Cow<'x, str>>,
        extension: BodyPartExtension<'x>,
    },
    Text {
        fields: BodyPartFields<'x>,
        body_size_lines: usize,
        // Extension data
        body_md5: Option<Cow<'x, str>>,
        extension: BodyPartExtension<'x>,
    },
    Message {
        fields: BodyPartFields<'x>,
        envelope: Option<Box<Envelope<'x>>>,
        body: Option<Box<BodyPart<'x>>>,
        body_size_lines: usize,
        // Extension data
        body_md5: Option<Cow<'x, str>>,
        extension: BodyPartExtension<'x>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BodyPartFields<'x> {
    pub body_subtype: Option<Cow<'x, str>>,
    pub body_parameters: Option<Vec<(Cow<'x, str>, Cow<'x, str>)>>,
    pub body_id: Option<Cow<'x, str>>,
    pub body_description: Option<Cow<'x, str>>,
    pub body_encoding: Option<Cow<'x, str>>,
    pub body_size_octets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::type_complexity)]
pub struct BodyPartExtension<'x> {
    pub body_disposition: Option<(Cow<'x, str>, Vec<(Cow<'x, str>, Cow<'x, str>)>)>,
    pub body_language: Option<Vec<Cow<'x, str>>>,
    pub body_location: Option<Cow<'x, str>>,
}

impl<'x> Address<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Single(addr) => addr.serialize(buf),
            Address::Group(addr) => addr.serialize(buf),
        }
    }

    pub fn into_owned<'y>(self) -> Address<'y> {
        match self {
            Address::Single(addr) => Address::Single(addr.into_owned()),
            Address::Group(addr) => Address::Group(addr.into_owned()),
        }
    }
}

impl<'x> EmailAddress<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(b'(');
        if let Some(name) = &self.name {
            quoted_or_literal_string(buf, name);
        } else {
            buf.extend_from_slice(b"NIL");
        }

        let addr = if let Some((route, addr)) = self.address.split_once(':') {
            buf.push(b' ');
            quoted_or_literal_string(buf, route);
            buf.push(b' ');
            addr
        } else {
            buf.extend_from_slice(b" NIL ");
            &self.address
        };

        if let Some((local, host)) = addr.split_once('@') {
            quoted_or_literal_string(buf, local);
            buf.push(b' ');
            quoted_or_literal_string(buf, host);
        } else {
            quoted_or_literal_string(buf, &self.address);
            buf.extend_from_slice(b" \"\"");
        }
        buf.push(b')');
    }

    pub fn into_owned<'y>(self) -> EmailAddress<'y> {
        EmailAddress {
            name: self.name.map(|n| n.into_owned().into()),
            address: self.address.into_owned().into(),
        }
    }
}

impl<'x> AddressGroup<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"(NIL NIL ");
        if let Some(name) = &self.name {
            quoted_or_literal_string(buf, name);
        } else {
            buf.extend_from_slice(b"\"\"");
        }
        buf.extend_from_slice(b" NIL)");
        for addr in &self.addresses {
            addr.serialize(buf);
        }
        buf.extend_from_slice(b"(NIL NIL NIL NIL)");
    }

    pub fn into_owned<'y>(self) -> AddressGroup<'y> {
        AddressGroup {
            name: self.name.map(|n| n.into_owned().into()),
            addresses: self
                .addresses
                .into_iter()
                .map(|addr| addr.into_owned())
                .collect(),
        }
    }
}

impl<'x> BodyPart<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_extended: bool) {
        buf.push(b'(');
        match self {
            BodyPart::Multipart {
                body_parts,
                body_subtype,
                body_parameters,
                extension,
            } => {
                for part in body_parts.iter() {
                    part.serialize(buf, is_extended);
                }
                buf.push(b' ');
                quoted_or_literal_string(buf, body_subtype);
                if is_extended {
                    if let Some(body_parameters) = body_parameters {
                        buf.extend_from_slice(b" (");
                        for (pos, (key, value)) in body_parameters.iter().enumerate() {
                            if pos > 0 {
                                buf.push(b' ');
                            }
                            quoted_or_literal_string(buf, key);
                            buf.push(b' ');
                            quoted_or_literal_string(buf, value);
                        }
                        buf.push(b')');
                    } else {
                        buf.extend_from_slice(b" NIL");
                    }
                    buf.push(b' ');
                    extension.serialize(buf);
                }
            }
            BodyPart::Basic {
                body_type,
                fields,
                body_md5,
                extension,
            } => {
                quoted_or_literal_string_or_nil(buf, body_type.as_deref());
                buf.push(b' ');
                fields.serialize(buf);
                if is_extended {
                    buf.push(b' ');
                    quoted_or_literal_string_or_nil(buf, body_md5.as_deref());
                    buf.push(b' ');
                    extension.serialize(buf);
                }
            }
            BodyPart::Text {
                fields,
                body_size_lines,
                body_md5,
                extension,
            } => {
                buf.extend_from_slice(b"\"text\" ");
                fields.serialize(buf);
                buf.push(b' ');
                buf.extend_from_slice(body_size_lines.to_string().as_bytes());
                if is_extended {
                    buf.push(b' ');
                    quoted_or_literal_string_or_nil(buf, body_md5.as_deref());
                    buf.push(b' ');
                    extension.serialize(buf);
                }
            }
            BodyPart::Message {
                fields,
                envelope,
                body,
                body_size_lines,
                body_md5,
                extension,
            } => {
                buf.extend_from_slice(b"\"message\" ");
                fields.serialize(buf);
                buf.push(b' ');
                if let Some(envelope) = envelope {
                    envelope.serialize(buf);
                } else {
                    buf.extend_from_slice(b"NIL");
                }
                buf.push(b' ');
                if let Some(body) = body {
                    body.serialize(buf, is_extended);
                } else {
                    buf.extend_from_slice(b"NIL");
                }
                buf.push(b' ');
                buf.extend_from_slice(body_size_lines.to_string().as_bytes());
                if is_extended {
                    buf.push(b' ');
                    quoted_or_literal_string_or_nil(buf, body_md5.as_deref());
                    buf.push(b' ');
                    extension.serialize(buf);
                }
            }
        }
        buf.push(b')');
    }

    pub fn add_part(&mut self, part: BodyPart<'x>) {
        match self {
            BodyPart::Multipart { body_parts, .. } => body_parts.push(part),
            BodyPart::Message { body, .. } => *body = Box::new(part).into(),
            _ => debug_assert!(false, "Cannot add a part to a non-multipart body part"),
        }
    }

    pub fn set_envelope(&mut self, envelope_: Envelope<'x>) {
        match self {
            BodyPart::Message { envelope, .. } => *envelope = Some(Box::new(envelope_)),
            _ => debug_assert!(false, "Cannot set envelope on a non-message body part"),
        }
    }

    pub fn into_owned<'y>(self) -> BodyPart<'y> {
        match self {
            BodyPart::Multipart {
                body_parts,
                body_subtype,
                body_parameters,
                extension,
            } => BodyPart::Multipart {
                body_parts: body_parts.into_iter().map(|v| v.into_owned()).collect(),
                body_subtype: body_subtype.into_owned().into(),
                body_parameters: body_parameters.map(|b| {
                    b.into_iter()
                        .map(|(k, v)| (k.into_owned().into(), v.into_owned().into()))
                        .collect::<Vec<_>>()
                }),
                extension: extension.into_owned(),
            },
            BodyPart::Basic {
                body_type,
                fields,
                body_md5,
                extension,
            } => BodyPart::Basic {
                body_type: body_type.map(|v| v.into_owned().into()),
                fields: fields.into_owned(),
                body_md5: body_md5.map(|v| v.into_owned().into()),
                extension: extension.into_owned(),
            },
            BodyPart::Text {
                fields,
                body_size_lines,
                body_md5,
                extension,
            } => BodyPart::Text {
                fields: fields.into_owned(),
                body_size_lines,
                body_md5: body_md5.map(|v| v.into_owned().into()),
                extension: extension.into_owned(),
            },
            BodyPart::Message {
                fields,
                envelope,
                body,
                body_size_lines,
                body_md5,
                extension,
            } => BodyPart::Message {
                fields: fields.into_owned(),
                envelope: envelope.map(|v| Box::new(v.into_owned())),
                body: body.map(|b| Box::new(b.into_owned())),
                body_size_lines,
                body_md5: body_md5.map(|v| v.into_owned().into()),
                extension: extension.into_owned(),
            },
        }
    }
}

impl<'x> BodyPartFields<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        quoted_or_literal_string_or_nil(buf, self.body_subtype.as_deref());
        if let Some(body_parameters) = &self.body_parameters {
            buf.extend_from_slice(b" (");
            for (pos, (key, value)) in body_parameters.iter().enumerate() {
                if pos > 0 {
                    buf.push(b' ');
                }
                quoted_or_literal_string(buf, key);
                buf.push(b' ');
                quoted_or_literal_string(buf, value);
            }
            buf.push(b')');
        } else {
            buf.extend_from_slice(b" NIL");
        }
        for item in [&self.body_id, &self.body_description, &self.body_encoding] {
            buf.push(b' ');
            quoted_or_literal_string_or_nil(buf, item.as_deref());
        }
        buf.push(b' ');
        buf.extend_from_slice(self.body_size_octets.to_string().as_bytes());
    }

    pub fn into_owned<'y>(self) -> BodyPartFields<'y> {
        BodyPartFields {
            body_subtype: self.body_subtype.map(|v| v.into_owned().into()),
            body_parameters: self.body_parameters.map(|b| {
                b.into_iter()
                    .map(|(k, v)| (k.into_owned().into(), v.into_owned().into()))
                    .collect::<Vec<_>>()
            }),
            body_id: self.body_id.map(|v| v.into_owned().into()),
            body_description: self.body_description.map(|v| v.into_owned().into()),
            body_encoding: self.body_encoding.map(|v| v.into_owned().into()),
            body_size_octets: self.body_size_octets,
        }
    }
}

impl<'x> BodyPartExtension<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        if let Some((disposition, parameters)) = &self.body_disposition {
            buf.push(b'(');
            quoted_or_literal_string(buf, disposition);
            if !parameters.is_empty() {
                buf.extend_from_slice(b" (");
                for (pos, (key, value)) in parameters.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    quoted_or_literal_string(buf, key);
                    buf.push(b' ');
                    quoted_or_literal_string(buf, value);
                }
                buf.extend_from_slice(b"))");
            } else {
                buf.extend_from_slice(b" NIL)");
            }
        } else {
            buf.extend_from_slice(b"NIL");
        }
        if let Some(body_language) = &self.body_language {
            match body_language.len() {
                0 => buf.extend_from_slice(b" NIL"),
                1 => {
                    buf.push(b' ');
                    quoted_or_literal_string(buf, body_language.last().unwrap());
                }
                _ => {
                    buf.extend_from_slice(b" (");
                    for (pos, lang) in body_language.iter().enumerate() {
                        if pos > 0 {
                            buf.push(b' ');
                        }
                        quoted_or_literal_string(buf, lang);
                    }
                    buf.push(b')');
                }
            }
        } else {
            buf.extend_from_slice(b" NIL");
        }
        buf.push(b' ');
        quoted_or_literal_string_or_nil(buf, self.body_location.as_deref());
    }

    pub fn into_owned<'y>(self) -> BodyPartExtension<'y> {
        BodyPartExtension {
            body_disposition: self.body_disposition.map(|(a, b)| {
                (
                    a.into_owned().into(),
                    b.into_iter()
                        .map(|(k, v)| (k.into_owned().into(), v.into_owned().into()))
                        .collect::<Vec<_>>(),
                )
            }),
            body_language: self
                .body_language
                .map(|v| v.into_iter().map(|a| a.into_owned().into()).collect()),
            body_location: self.body_location.map(|v| v.into_owned().into()),
        }
    }
}

impl<'x> BodyContents<'x> {
    pub fn into_owned<'y>(self) -> BodyContents<'y> {
        match self {
            BodyContents::Text(text) => BodyContents::Text(text.into_owned().into()),
            BodyContents::Bytes(bytes) => BodyContents::Bytes(bytes.into_owned().into()),
        }
    }
}

impl Section {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Section::Part { num } => {
                buf.extend_from_slice(num.to_string().as_bytes());
            }
            Section::Header => {
                buf.extend_from_slice(b"HEADER");
            }
            Section::HeaderFields { not, fields } => {
                if !not {
                    buf.extend_from_slice(b"HEADER.FIELDS ");
                } else {
                    buf.extend_from_slice(b"HEADER.FIELDS.NOT ");
                }
                buf.push(b'(');
                for (pos, field) in fields.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    buf.extend_from_slice(field.as_str().to_ascii_uppercase().as_bytes());
                }
                buf.push(b')');
            }
            Section::Text => {
                buf.extend_from_slice(b"TEXT");
            }
            Section::Mime => {
                buf.extend_from_slice(b"MIME");
            }
        };
    }
}

static DUMMY_ADDRESS: [Address; 1] = [Address::Single(EmailAddress {
    name: None,
    address: Cow::Borrowed("unknown@localhost"),
})];

impl<'x> Envelope<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(b'(');
        quoted_rfc2822_or_nil(buf, &self.date);
        buf.push(b' ');
        quoted_or_literal_string_or_nil(buf, self.subject.as_deref());

        // Note: [RFC-2822] requires that all messages have a valid
        // From header.  Therefore, the from, sender, and reply-to
        // members in the envelope can not be NIL.

        let from = if !self.from.is_empty() {
            &self.from[..]
        } else {
            &DUMMY_ADDRESS[..]
        };

        self.serialize_addresses(buf, from);
        self.serialize_addresses(
            buf,
            if !self.sender.is_empty() {
                &self.sender
            } else {
                from
            },
        );
        self.serialize_addresses(
            buf,
            if !self.reply_to.is_empty() {
                &self.reply_to
            } else {
                from
            },
        );
        self.serialize_addresses(buf, &self.to);
        self.serialize_addresses(buf, &self.cc);
        self.serialize_addresses(buf, &self.bcc);
        for item in [&self.in_reply_to, &self.message_id] {
            buf.push(b' ');
            quoted_or_literal_string_or_nil(buf, item.as_deref());
        }
        buf.push(b')');
    }

    fn serialize_addresses(&self, buf: &mut Vec<u8>, addresses: &[Address]) {
        buf.push(b' ');
        if !addresses.is_empty() {
            buf.push(b'(');
            for address in addresses {
                address.serialize(buf);
            }
            buf.push(b')');
        } else {
            buf.extend_from_slice(b"NIL");
        }
    }

    pub fn into_owned<'y>(self) -> Envelope<'y> {
        Envelope {
            date: self.date,
            subject: self.subject.map(|v| v.into_owned().into()),
            from: self.from.into_iter().map(|v| v.into_owned()).collect(),
            sender: self.sender.into_iter().map(|v| v.into_owned()).collect(),
            reply_to: self.reply_to.into_iter().map(|v| v.into_owned()).collect(),
            to: self.to.into_iter().map(|v| v.into_owned()).collect(),
            cc: self.cc.into_iter().map(|v| v.into_owned()).collect(),
            bcc: self.bcc.into_iter().map(|v| v.into_owned()).collect(),
            in_reply_to: self.in_reply_to.map(|v| v.into_owned().into()),
            message_id: self.message_id.map(|v| v.into_owned().into()),
        }
    }
}

impl<'x> DataItem<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            DataItem::Binary {
                sections,
                offset,
                contents,
            } => {
                buf.extend_from_slice(b"BINARY[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    buf.extend_from_slice(section.to_string().as_bytes());
                }
                if let Some(offset) = offset {
                    buf.extend_from_slice(b"]<");
                    buf.extend_from_slice(offset.to_string().as_bytes());
                    buf.extend_from_slice(b"> ");
                } else {
                    buf.extend_from_slice(b"] ");
                }
                match contents {
                    BodyContents::Text(text) => {
                        literal_string(buf, text.as_bytes());
                    }
                    BodyContents::Bytes(bytes) => {
                        buf.extend_from_slice(b"~{");
                        buf.extend_from_slice(bytes.len().to_string().as_bytes());
                        buf.extend_from_slice(b"}\r\n");
                        buf.extend_from_slice(bytes);
                    }
                }
            }
            DataItem::BinarySize { sections, size } => {
                buf.extend_from_slice(b"BINARY.SIZE[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    buf.extend_from_slice(section.to_string().as_bytes());
                }
                buf.extend_from_slice(b"] ");
                buf.extend_from_slice(size.to_string().as_bytes());
            }
            DataItem::Body { part } => {
                buf.extend_from_slice(b"BODY ");
                part.serialize(buf, false);
            }
            DataItem::BodyStructure { part } => {
                buf.extend_from_slice(b"BODYSTRUCTURE ");
                part.serialize(buf, true);
            }
            DataItem::BodySection {
                sections,
                origin_octet,
                contents,
            } => {
                buf.extend_from_slice(b"BODY[");
                for (pos, section) in sections.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b'.');
                    }
                    section.serialize(buf);
                }
                if let Some(origin_octet) = origin_octet {
                    buf.extend_from_slice(b"]<");
                    buf.extend_from_slice(origin_octet.to_string().as_bytes());
                    buf.extend_from_slice(b"> ");
                } else {
                    buf.extend_from_slice(b"] ");
                }
                literal_string(buf, contents);
            }
            DataItem::Envelope { envelope } => {
                buf.extend_from_slice(b"ENVELOPE ");
                envelope.serialize(buf);
            }
            DataItem::Flags { flags } => {
                buf.extend_from_slice(b"FLAGS (");
                for (pos, flag) in flags.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    flag.serialize(buf);
                }
                buf.push(b')');
            }
            DataItem::InternalDate { date } => {
                buf.extend_from_slice(b"INTERNALDATE ");
                quoted_timestamp(buf, *date);
            }
            DataItem::Uid { uid } => {
                buf.extend_from_slice(b"UID ");
                buf.extend_from_slice(uid.to_string().as_bytes());
            }
            DataItem::Rfc822 { contents } => {
                buf.extend_from_slice(b"RFC822 ");
                literal_string(buf, contents);
            }
            DataItem::Rfc822Header { contents } => {
                buf.extend_from_slice(b"RFC822.HEADER ");
                literal_string(buf, contents);
            }
            DataItem::Rfc822Size { size } => {
                buf.extend_from_slice(b"RFC822.SIZE ");
                buf.extend_from_slice(size.to_string().as_bytes());
            }
            DataItem::Rfc822Text { contents } => {
                buf.extend_from_slice(b"RFC822.TEXT ");
                literal_string(buf, contents);
            }
            DataItem::Preview { contents } => {
                buf.extend_from_slice(b"PREVIEW ");
                if let Some(contents) = contents {
                    literal_string(buf, contents);
                } else {
                    buf.extend_from_slice(b"NIL");
                }
            }
            DataItem::ModSeq { modseq } => {
                buf.extend_from_slice(b"MODSEQ (");
                buf.extend_from_slice(modseq.to_string().as_bytes());
                buf.push(b')');
            }
            DataItem::EmailId { email_id } => {
                buf.extend_from_slice(b"EMAILID (");
                buf.extend_from_slice(email_id.as_bytes());
                buf.push(b')');
            }
            DataItem::ThreadId { thread_id } => {
                buf.extend_from_slice(b"THREADID (");
                buf.extend_from_slice(thread_id.as_bytes());
                buf.push(b')');
            }
        }
    }
}

impl<'x> FetchItem<'x> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* ");
        buf.extend_from_slice(self.id.to_string().as_bytes());
        buf.extend_from_slice(b" FETCH (");
        for (pos, item) in self.items.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            item.serialize(buf);
        }
        buf.extend_from_slice(b")\r\n");
    }
}

impl<'x> ImapResponse for Response<'x> {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        for item in &self.items {
            item.serialize(&mut buf);
        }
        buf
    }
}

/*

   body            = "(" (body-type-1part / body-type-mpart) ")"

   body-type-1part = (body-type-basic / body-type-msg / body-type-text)
                     [SP body-ext-1part]

   body-type-basic = media-basic SP body-fields
                       ; MESSAGE subtype MUST NOT be "RFC822" or
                       ; "GLOBAL"

   body-type-mpart = 1*body SP media-subtype
                     [SP body-ext-mpart]
                       ; MULTIPART body part

   body-type-msg   = media-message SP body-fields SP envelope
                     SP body SP body-fld-lines

   body-type-text  = media-text SP body-fields SP body-fld-lines

   body-fields     = body-fld-param SP body-fld-id SP body-fld-desc SP
                     body-fld-enc SP body-fld-octets

   media-message   = DQUOTE "MESSAGE" DQUOTE SP
                     DQUOTE ("RFC822" / "GLOBAL") DQUOTE
                       ; Defined in [MIME-IMT]

   media-basic     = ((DQUOTE ("APPLICATION" / "AUDIO" / "IMAGE" /
                     "FONT" / "MESSAGE" / "MODEL" / "VIDEO" ) DQUOTE)
                     / string)
                     SP media-subtype

   envelope        = "(" env-date SP env-subject SP env-from SP
                     env-sender SP env-reply-to SP env-to SP env-cc SP
                     env-bcc SP env-in-reply-to SP env-message-id ")"

   body-fld-lines  = number64

*/

#[cfg(test)]
mod tests {

    use mail_parser::DateTime;

    use crate::protocol::{Flag, ImapResponse};

    use super::{
        Address, AddressGroup, BodyPart, BodyPartExtension, BodyPartFields, DataItem, EmailAddress,
        Envelope, FetchItem, Response, Section,
    };

    #[test]
    fn serialize_fetch_data_item() {
        for (item, expected_response) in [
            (
                super::DataItem::Envelope {
                    envelope: Envelope {
                        date: DateTime::from_timestamp(837570205).into(),
                        subject: Some("IMAP4rev2 WG mtg summary and minutes".into()),
                        from: vec![Address::Single(EmailAddress {
                            name: Some("Terry Gray".into()),
                            address: "gray@cac.washington.edu".into(),
                        })],
                        sender: vec![Address::Single(EmailAddress {
                            name: Some("Terry Gray".into()),
                            address: "gray@cac.washington.edu".into(),
                        })],
                        reply_to: vec![Address::Single(EmailAddress {
                            name: Some("Terry Gray".into()),
                            address: "gray@cac.washington.edu".into(),
                        })],
                        to: vec![Address::Single(EmailAddress {
                            name: None,
                            address: "imap@cac.washington.edu".into(),
                        })],
                        cc: vec![
                            Address::Single(EmailAddress {
                                name: None,
                                address: "minutes@CNRI.Reston.VA.US".into(),
                            }),
                            Address::Single(EmailAddress {
                                name: Some("John Klensin".into()),
                                address: "KLENSIN@MIT.EDU".into(),
                            }),
                        ],
                        bcc: vec![],
                        in_reply_to: None,
                        message_id: Some("<B27397-0100000@cac.washington.ed>".into()),
                    },
                },
                concat!(
                    "ENVELOPE (\"Wed, 17 Jul 1996 02:23:25 +0000\" ",
                    "\"IMAP4rev2 WG mtg summary and minutes\" ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((NIL NIL \"imap\" \"cac.washington.edu\")) ",
                    "((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")",
                    "(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) NIL NIL ",
                    "\"<B27397-0100000@cac.washington.ed>\")"
                ),
            ),
            (
                super::DataItem::Envelope {
                    envelope: Envelope {
                        date: DateTime::from_timestamp(837570205).into(),
                        subject: Some("Group test".into()),
                        from: vec![Address::Single(EmailAddress {
                            name: Some("Bill Foobar".into()),
                            address: "foobar@example.com".into(),
                        })],
                        sender: vec![],
                        reply_to: vec![],
                        to: vec![Address::Group(AddressGroup {
                            name: Some("Friends and Family".into()),
                            addresses: vec![
                                EmailAddress {
                                    name: Some("John Doe".into()),
                                    address: "jdoe@example.com".into(),
                                },
                                EmailAddress {
                                    name: Some("Jane Smith".into()),
                                    address: "jane.smith@example.com".into(),
                                },
                            ],
                        })],
                        cc: vec![],
                        bcc: vec![],
                        in_reply_to: None,
                        message_id: Some("<B27397-0100000@cac.washington.ed>".into()),
                    },
                },
                concat!(
                    "ENVELOPE (\"Wed, 17 Jul 1996 02:23:25 +0000\" ",
                    "\"Group test\" ",
                    "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                    "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                    "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                    "((NIL NIL \"Friends and Family\" NIL)",
                    "(\"John Doe\" NIL \"jdoe\" \"example.com\")",
                    "(\"Jane Smith\" NIL \"jane.smith\" \"example.com\")",
                    "(NIL NIL NIL NIL)) ",
                    "NIL NIL NIL \"<B27397-0100000@cac.washington.ed>\")"
                ),
            ),
            (
                super::DataItem::Body {
                    part: BodyPart::Text {
                        fields: BodyPartFields {
                            body_subtype: Some("PLAIN".into()),
                            body_parameters: vec![("CHARSET".into(), "US-ASCII".into())].into(),
                            body_id: None,
                            body_description: None,
                            body_encoding: Some("7BIT".into()),
                            body_size_octets: 2279,
                        },
                        body_size_lines: 48,
                        body_md5: None,
                        extension: BodyPartExtension {
                            body_disposition: None,
                            body_language: None,
                            body_location: None,
                        },
                    },
                },
                "BODY (\"text\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 2279 48)",
            ),
            (
                super::DataItem::Body {
                    part: BodyPart::Message {
                        fields: BodyPartFields {
                            body_subtype: Some("RFC822".into()),
                            body_parameters: None,
                            body_id: Some("<abc@123>".into()),
                            body_description: Some("An attached email".into()),
                            body_encoding: Some("quoted-printable".into()),
                            body_size_octets: 9323,
                        },
                        envelope: Box::new(Envelope {
                            date: DateTime::from_timestamp(837570205).into(),
                            subject: Some("Hello world!".into()),
                            from: vec![Address::Single(EmailAddress {
                                name: Some("Terry Gray".into()),
                                address: "gray@cac.washington.edu".into(),
                            })],
                            sender: vec![Address::Single(EmailAddress {
                                name: Some("Terry Gray".into()),
                                address: "gray@cac.washington.edu".into(),
                            })],
                            reply_to: vec![Address::Single(EmailAddress {
                                name: Some("Terry Gray".into()),
                                address: "gray@cac.washington.edu".into(),
                            })],
                            to: vec![Address::Single(EmailAddress {
                                name: None,
                                address: "imap@cac.washington.edu".into(),
                            })],
                            cc: vec![],
                            bcc: vec![],
                            in_reply_to: None,
                            message_id: Some("<4234324@domain.com>".into()),
                        })
                        .into(),
                        body: Box::new(BodyPart::Text {
                            fields: BodyPartFields {
                                body_subtype: Some("HTML".into()),
                                body_parameters: None,
                                body_id: None,
                                body_description: None,
                                body_encoding: Some("8BIT".into()),
                                body_size_octets: 4234,
                            },
                            body_size_lines: 431,
                            body_md5: None,
                            extension: BodyPartExtension {
                                body_disposition: None,
                                body_language: None,
                                body_location: None,
                            },
                        })
                        .into(),
                        body_size_lines: 908,
                        body_md5: None,
                        extension: BodyPartExtension {
                            body_disposition: None,
                            body_language: None,
                            body_location: None,
                        },
                    },
                },
                concat!(
                    "BODY (\"message\" \"RFC822\" NIL \"<abc@123>\" \"An attached email\" ",
                    "\"quoted-printable\" 9323 (\"Wed, 17 Jul 1996 02:23:25 +0000\" ",
                    "\"Hello world!\" ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                    "((NIL NIL \"imap\" \"cac.washington.edu\")) NIL NIL NIL ",
                    "\"<4234324@domain.com>\") (\"text\" \"HTML\" NIL NIL NIL ",
                    "\"8BIT\" 4234 431) 908)"
                ),
            ),
            (
                super::DataItem::Body {
                    part: BodyPart::Multipart {
                        body_parts: vec![
                            BodyPart::Text {
                                fields: BodyPartFields {
                                    body_subtype: Some("PLAIN".into()),
                                    body_parameters: vec![("CHARSET".into(), "US-ASCII".into())]
                                        .into(),
                                    body_id: None,
                                    body_description: None,
                                    body_encoding: Some("7BIT".into()),
                                    body_size_octets: 1152,
                                },
                                body_size_lines: 23,
                                body_md5: None,
                                extension: BodyPartExtension {
                                    body_disposition: None,
                                    body_language: None,
                                    body_location: None,
                                },
                            },
                            BodyPart::Text {
                                fields: BodyPartFields {
                                    body_subtype: Some("PLAIN".into()),
                                    body_parameters: vec![
                                        ("CHARSET".into(), "US-ASCII".into()),
                                        ("NAME".into(), "cc.diff".into()),
                                    ]
                                    .into(),
                                    body_id: Some(
                                        "<960723163407.20117h@cac.washington.edu>".into(),
                                    ),
                                    body_description: Some("Compiler diff".into()),
                                    body_encoding: Some("BASE64".into()),
                                    body_size_octets: 4554,
                                },
                                body_size_lines: 73,
                                body_md5: None,
                                extension: BodyPartExtension {
                                    body_disposition: None,
                                    body_language: None,
                                    body_location: None,
                                },
                            },
                        ],
                        body_subtype: "MIXED".into(),
                        body_parameters: None,
                        extension: BodyPartExtension {
                            body_disposition: None,
                            body_language: None,
                            body_location: None,
                        },
                    },
                },
                concat!(
                    "BODY ((\"text\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") ",
                    "NIL NIL \"7BIT\" 1152 23)",
                    "(\"text\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\" \"NAME\" \"cc.diff\") ",
                    "\"<960723163407.20117h@cac.washington.edu>\" \"Compiler diff\" ",
                    "\"BASE64\" 4554 73) \"MIXED\")",
                ),
            ),
            (
                DataItem::BodyStructure {
                    part: BodyPart::Multipart {
                        body_parts: vec![
                            BodyPart::Multipart {
                                body_parts: vec![
                                    BodyPart::Text {
                                        fields: BodyPartFields {
                                            body_subtype: Some("PLAIN".into()),
                                            body_parameters: vec![(
                                                "CHARSET".into(),
                                                "UTF-8".into(),
                                            )]
                                            .into(),
                                            body_id: Some("<111@domain.com>".into()),
                                            body_description: Some("Text part".into()),
                                            body_encoding: Some("7BIT".into()),
                                            body_size_octets: 1152,
                                        },
                                        body_size_lines: 23,
                                        body_md5: Some("8o3456".into()),
                                        extension: BodyPartExtension {
                                            body_disposition: ("inline".into(), vec![]).into(),
                                            body_language: vec!["en-US".into()].into(),
                                            body_location: Some("right here".into()),
                                        },
                                    },
                                    BodyPart::Text {
                                        fields: BodyPartFields {
                                            body_subtype: Some("HTML".into()),
                                            body_parameters: vec![(
                                                "CHARSET".into(),
                                                "UTF-8".into(),
                                            )]
                                            .into(),
                                            body_id: Some("<54535@domain.com>".into()),
                                            body_description: Some("HTML part".into()),
                                            body_encoding: Some("8BIT".into()),
                                            body_size_octets: 45345,
                                        },
                                        body_size_lines: 994,
                                        body_md5: Some("53454".into()),
                                        extension: BodyPartExtension {
                                            body_disposition: (
                                                "attachment".into(),
                                                vec![("filename".into(), "myfile.txt".into())],
                                            )
                                                .into(),
                                            body_language: vec!["en-US".into(), "de-DE".into()]
                                                .into(),
                                            body_location: Some("right there".into()),
                                        },
                                    },
                                ],
                                body_subtype: "ALTERNATIVE".into(),
                                body_parameters: vec![(
                                    "x-param".into(),
                                    "a very special parameter".into(),
                                )]
                                .into(),
                                extension: BodyPartExtension {
                                    body_disposition: None,
                                    body_language: vec!["en-US".into()].into(),
                                    body_location: Some("unknown".into()),
                                },
                            },
                            BodyPart::Basic {
                                body_type: Some("APPLICATION".into()),
                                fields: BodyPartFields {
                                    body_subtype: Some("MSWORD".into()),
                                    body_parameters: vec![(
                                        "NAME".into(),
                                        "chimichangas.docx".into(),
                                    )]
                                    .into(),
                                    body_id: Some("<4444@chimi.changa>".into()),
                                    body_description: Some("Chimichangas recipe".into()),
                                    body_encoding: Some("base64".into()),
                                    body_size_octets: 84723,
                                },
                                body_md5: Some("1234".into()),
                                extension: BodyPartExtension {
                                    body_disposition: (
                                        "attachment".into(),
                                        vec![("filename".into(), "chimichangas.docx".into())],
                                    )
                                        .into(),
                                    body_language: vec!["en-MX".into()].into(),
                                    body_location: Some("secret location".into()),
                                },
                            },
                        ],
                        body_subtype: "MIXED".into(),
                        body_parameters: None,
                        extension: BodyPartExtension {
                            body_disposition: None,
                            body_language: None,
                            body_location: None,
                        },
                    },
                },
                concat!(
                    "BODYSTRUCTURE (((\"text\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") ",
                    "\"<111@domain.com>\" \"Text part\" \"7BIT\" 1152 23 \"8o3456\" ",
                    "(\"inline\" NIL) \"en-US\" \"right here\")",
                    "(\"text\" \"HTML\" (\"CHARSET\" \"UTF-8\") ",
                    "\"<54535@domain.com>\" \"HTML part\" \"8BIT\" 45345 994 \"53454\" ",
                    "(\"attachment\" (\"filename\" \"myfile.txt\")) ",
                    "(\"en-US\" \"de-DE\") ",
                    "\"right there\") \"ALTERNATIVE\" (\"x-param\" ",
                    "\"a very special parameter\") ",
                    "NIL \"en-US\" \"unknown\")",
                    "(\"APPLICATION\" \"MSWORD\" (\"NAME\" \"chimichangas.docx\") ",
                    "\"<4444@chimi.changa>\" \"Chimichangas recipe\" \"base64\"",
                    " 84723 \"1234\" ",
                    "(\"attachment\" (\"filename\" \"chimichangas.docx\")) \"en-MX\" ",
                    "\"secret location\") \"MIXED\" NIL NIL NIL NIL)",
                ),
            ),
            (
                super::DataItem::Binary {
                    sections: vec![1, 2, 3],
                    offset: 10.into(),
                    contents: super::BodyContents::Bytes(b"hello".to_vec().into()),
                },
                "BINARY[1.2.3]<10> ~{5}\r\nhello",
            ),
            (
                super::DataItem::Binary {
                    sections: vec![1, 2, 3],
                    offset: None,
                    contents: super::BodyContents::Text("hello".into()),
                },
                "BINARY[1.2.3] {5}\r\nhello",
            ),
            (
                super::DataItem::BodySection {
                    sections: vec![
                        Section::Part { num: 1 },
                        Section::Part { num: 2 },
                        Section::Mime,
                    ],
                    origin_octet: 11.into(),
                    contents: b"howdy"[..].into(),
                },
                "BODY[1.2.MIME]<11> {5}\r\nhowdy",
            ),
            (
                super::DataItem::BodySection {
                    sections: vec![Section::HeaderFields {
                        not: true,
                        fields: vec!["Subject".into(), "x-special".into()],
                    }],
                    origin_octet: None,
                    contents: b"howdy"[..].into(),
                },
                "BODY[HEADER.FIELDS.NOT (SUBJECT X-SPECIAL)] {5}\r\nhowdy",
            ),
            (
                super::DataItem::BodySection {
                    sections: vec![Section::HeaderFields {
                        not: false,
                        fields: vec!["From".into(), "List-Archive".into()],
                    }],
                    origin_octet: None,
                    contents: b"howdy"[..].into(),
                },
                "BODY[HEADER.FIELDS (FROM LIST-ARCHIVE)] {5}\r\nhowdy",
            ),
            (
                super::DataItem::Flags {
                    flags: vec![Flag::Seen],
                },
                "FLAGS (\\Seen)",
            ),
            (
                super::DataItem::InternalDate { date: 482374938 },
                "INTERNALDATE \"15-Apr-1985 01:02:18 +0000\"",
            ),
        ] {
            let mut buf = Vec::with_capacity(100);

            item.serialize(&mut buf);

            assert_eq!(String::from_utf8(buf).unwrap(), expected_response);
        }
    }

    #[test]
    fn serialize_fetch() {
        assert_eq!(
            String::from_utf8(
                Response {
                    is_uid: false,
                    items: vec![FetchItem {
                        id: 123,
                        items: vec![
                            super::DataItem::Flags {
                                flags: vec![Flag::Deleted, Flag::Flagged],
                            },
                            super::DataItem::Uid { uid: 983 },
                            super::DataItem::Rfc822Size { size: 443 },
                            super::DataItem::Rfc822Text {
                                contents: b"hi"[..].into()
                            },
                            super::DataItem::Rfc822Header {
                                contents: b"header"[..].into()
                            },
                        ],
                    }],
                }
                .serialize(),
            )
            .unwrap(),
            concat!(
                "* 123 FETCH (FLAGS (\\Deleted \\Flagged) ",
                "UID 983 ",
                "RFC822.SIZE 443 ",
                "RFC822.TEXT {2}\r\nhi ",
                "RFC822.HEADER {6}\r\nheader)\r\n",
            )
        );
    }
}
