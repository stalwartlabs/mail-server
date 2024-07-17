/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{Display, Formatter};

use mail_parser::HeaderName;
use serde::Serialize;
use store::write::{DeserializeFrom, SerializeInto};

use crate::parser::{json::Parser, JsonObjectParser};

use super::{acl::Acl, id::Id, keyword::Keyword, value::Value};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Property {
    Acl,
    Aliases,
    Attachments,
    Bcc,
    BlobId,
    BodyStructure,
    BodyValues,
    Capabilities,
    Cc,
    Charset,
    Cid,
    DeliveryStatus,
    Description,
    DeviceClientId,
    Disposition,
    DsnBlobIds,
    Email,
    EmailId,
    EmailIds,
    Envelope,
    Expires,
    From,
    FromDate,
    HasAttachment,
    Header(HeaderProperty),
    Headers,
    HtmlBody,
    HtmlSignature,
    Id,
    IdentityId,
    InReplyTo,
    IsActive,
    IsEnabled,
    IsSubscribed,
    Keys,
    Keywords,
    Language,
    Location,
    MailboxIds,
    MayDelete,
    MdnBlobIds,
    Members,
    MessageId,
    MyRights,
    Name,
    ParentId,
    PartId,
    Picture,
    Preview,
    Quota,
    ReceivedAt,
    References,
    ReplyTo,
    Role,
    Secret,
    SendAt,
    Sender,
    SentAt,
    Size,
    SortOrder,
    Subject,
    SubParts,
    TextBody,
    TextSignature,
    ThreadId,
    Timezone,
    To,
    ToDate,
    TotalEmails,
    TotalThreads,
    Type,
    Types,
    UndoStatus,
    UnreadEmails,
    UnreadThreads,
    Url,
    VerificationCode,
    Addresses,
    P256dh,
    Auth,
    Value,
    SmtpReply,
    Delivered,
    Displayed,
    MailFrom,
    RcptTo,
    Parameters,
    IsEncodingProblem,
    IsTruncated,
    MayReadItems,
    MayAddItems,
    MayRemoveItems,
    MaySetSeen,
    MaySetKeywords,
    MayCreateChild,
    MayRename,
    MaySubmit,
    ResourceType,
    Used,
    HardLimit,
    WarnLimit,
    SoftLimit,
    Scope,
    Digest(DigestProperty),
    Data(DataProperty),
    _T(String),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DigestProperty {
    Sha,
    Sha256,
    Sha512,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DataProperty {
    AsText,
    AsBase64,
    Default,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SetProperty {
    pub property: Property,
    pub patch: Vec<Value>,
    pub is_ref: bool,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ObjectProperty(Property);

pub trait IntoProperty: Eq + Display {
    fn into_property(self) -> Property;
}

impl JsonObjectParser for Property {
    fn parse(parser: &mut Parser) -> trc::Result<Self> {
        let mut first_char = 0;
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if ch.is_ascii_alphabetic() {
                if first_char != 0 {
                    if shift < 128 {
                        hash |= (ch as u128) << shift;
                        shift += 8;
                    } else {
                        return parser.invalid_property();
                    }
                } else {
                    first_char = ch;
                }
            } else if ch == b':' {
                return if first_char == b'h' && hash == 0x0072_6564_6165 {
                    parse_header_property(parser)
                } else {
                    parse_sub_property(parser, first_char, hash)
                };
            } else {
                return parser.invalid_property();
            }
        }

        if let Some(property) = parse_property(first_char, hash) {
            Ok(property)
        } else {
            parser.invalid_property()
        }
    }
}

impl JsonObjectParser for SetProperty {
    fn parse(parser: &mut Parser) -> trc::Result<Self> {
        let mut first_char = 0;
        let mut hash = 0;
        let mut shift = 0;
        let mut is_ref = false;
        let mut is_patch = false;

        while let Some(ch) = parser.next_unescaped()? {
            if ch.is_ascii_alphabetic() {
                if first_char != 0 {
                    if shift < 128 {
                        hash |= (ch as u128) << shift;
                        shift += 8;
                    } else {
                        return parser.invalid_property().map(|property| SetProperty {
                            property,
                            patch: vec![],
                            is_ref: false,
                        });
                    }
                } else {
                    first_char = ch;
                }
            } else {
                match ch {
                    b'#' if first_char == 0 && !is_ref => is_ref = true,
                    b'/' if !is_ref => {
                        is_patch = true;
                        break;
                    }
                    b':' if first_char == b'h' && hash == 0x0072_6564_6165 && !is_ref => {
                        return parse_header_property(parser).map(|property| SetProperty {
                            property,
                            patch: vec![],
                            is_ref: false,
                        });
                    }
                    _ => {
                        return parser.invalid_property().map(|property| SetProperty {
                            property,
                            patch: vec![],
                            is_ref: false,
                        });
                    }
                }
            }
        }

        let mut property = if let Some(property) = parse_property(first_char, hash) {
            property
        } else {
            parser.invalid_property()?
        };
        let mut patch = Vec::new();

        if is_patch {
            match &property {
                Property::MailboxIds | Property::Members => match Id::parse(parser) {
                    Ok(id) => {
                        patch.push(Value::Id(id));
                    }
                    Err(err) if err.is_jmap_method_error() => {
                        property = parser.invalid_property()?;
                    }
                    Err(err) => {
                        return Err(err);
                    }
                },
                Property::Keywords => match Keyword::parse(parser) {
                    Ok(keyword) => {
                        patch.push(Value::Keyword(keyword));
                    }
                    Err(err) if err.is_jmap_method_error() => {
                        property = parser.invalid_property()?;
                    }
                    Err(err) => {
                        return Err(err);
                    }
                },
                Property::Acl => {
                    let mut has_acl = false;
                    let mut account = Vec::with_capacity(16);

                    while let Some(ch) = parser.next_unescaped()? {
                        if ch != b'/' {
                            account.push(ch);
                        } else {
                            has_acl = true;
                            break;
                        }
                    }

                    match String::from_utf8(account) {
                        Ok(account) if !account.is_empty() => {
                            patch.push(Value::Text(account));
                            if has_acl {
                                match Acl::parse(parser) {
                                    Ok(acl) => {
                                        patch.push(Value::UnsignedInt(acl as u64));
                                    }
                                    Err(err) if err.is_jmap_method_error() => {
                                        property = parser.invalid_property()?;
                                    }
                                    Err(err) => {
                                        return Err(err);
                                    }
                                }
                            }
                        }
                        _ => {
                            property = parser.invalid_property()?;
                        }
                    }
                }
                Property::Aliases => match String::parse(parser) {
                    Ok(text) if !text.is_empty() => {
                        patch.push(Value::Text(text));
                    }
                    Err(err) => {
                        return Err(err);
                    }
                    _ => {
                        property = parser.invalid_property()?;
                    }
                },
                _ => {
                    property = parser.invalid_property()?;
                }
            }
        }

        Ok(SetProperty {
            property,
            patch,
            is_ref,
        })
    }
}

fn parse_property(first_char: u8, hash: u128) -> Option<Property> {
    Some(match first_char {
        b'a' => match hash {
            0x6c63 => Property::Acl,
            0x7365_7361_696c => Property::Aliases,
            0x7374_6e65_6d68_6361_7474 => Property::Attachments,
            _ => return None,
        },
        b'b' => match hash {
            0x6363 => Property::Bcc,
            0x0064_4962_6f6c => Property::BlobId,
            0x6572_7574_6375_7274_5379_646f => Property::BodyStructure,
            0x0073_6575_6c61_5679_646f => Property::BodyValues,
            _ => return None,
        },
        b'c' => match hash {
            0x0073_6569_7469_6c69_6261_7061 => Property::Capabilities,
            0x63 => Property::Cc,
            0x7465_7372_6168 => Property::Charset,
            0x6469 => Property::Cid,
            _ => return None,
        },
        b'd' => match hash {
            0x0073_7574_6174_5379_7265_7669_6c65 => Property::DeliveryStatus,
            0x6e6f_6974_7069_7263_7365 => Property::Description,
            0x0064_4974_6e65_696c_4365_6369_7665 => Property::DeviceClientId,
            0x6e6f_6974_6973_6f70_7369 => Property::Disposition,
            0x0073_6449_626f_6c42_6e73 => Property::DsnBlobIds,
            0x0061_7461 => Property::Data(DataProperty::Default),
            _ => return None,
        },
        b'e' => match hash {
            0x6c69_616d => Property::Email,
            0x6449_6c69_616d => Property::EmailId,
            0x0073_6449_6c69_616d => Property::EmailIds,
            0x0065_706f_6c65_766e => Property::Envelope,
            0x7365_7269_7078 => Property::Expires,
            _ => return None,
        },
        b'f' => match hash {
            0x006d_6f72 => Property::From,
            0x0065_7461_446d_6f72 => Property::FromDate,
            _ => return None,
        },
        b'h' => match hash {
            0x746e_656d_6863_6174_7441_7361 => Property::HasAttachment,
            0x7372_6564_6165 => Property::Headers,
            0x0079_646f_426c_6d74 => Property::HtmlBody,
            0x6572_7574_616e_6769_536c_6d74 => Property::HtmlSignature,
            _ => return None,
        },
        b'i' => match hash {
            0x64 => Property::Id,
            0x0064_4979_7469_746e_6564 => Property::IdentityId,
            0x6f54_796c_7065_526e => Property::InReplyTo,
            0x0065_7669_7463_4173 => Property::IsActive,
            0x6465_6c62_616e_4573 => Property::IsEnabled,
            0x0064_6562_6972_6373_6275_5373 => Property::IsSubscribed,
            _ => return None,
        },
        b'k' => match hash {
            0x0073_7965 => Property::Keys,
            0x0073_6472_6f77_7965 => Property::Keywords,
            _ => return None,
        },
        b'l' => match hash {
            0x0065_6761_7567_6e61 => Property::Language,
            0x006e_6f69_7461_636f => Property::Location,
            _ => return None,
        },
        b'm' => match hash {
            0x0073_6449_786f_626c_6961 => Property::MailboxIds,
            0x6574_656c_6544_7961 => Property::MayDelete,
            0x0073_6449_626f_6c42_6e64 => Property::MdnBlobIds,
            0x7372_6562_6d65 => Property::Members,
            0x6449_6567_6173_7365 => Property::MessageId,
            0x0073_7468_6769_5279 => Property::MyRights,
            _ => return None,
        },
        b'n' => match hash {
            0x0065_6d61 => Property::Name,
            _ => return None,
        },
        b'p' => match hash {
            0x0064_4974_6e65_7261 => Property::ParentId,
            0x0064_4974_7261 => Property::PartId,
            0x6572_7574_6369 => Property::Picture,
            0x7765_6976_6572 => Property::Preview,
            _ => return None,
        },
        b'q' => match hash {
            0x6174_6f75 => Property::Quota,
            _ => return None,
        },
        b'r' => match hash {
            0x0074_4164_6576_6965_6365 => Property::ReceivedAt,
            0x0073_6563_6e65_7265_6665 => Property::References,
            0x6f54_796c_7065 => Property::ReplyTo,
            0x0065_6c6f => Property::Role,
            _ => return None,
        },
        b's' => match hash {
            0x0074_6572_6365 => Property::Secret,
            0x0074_4164_6e65 => Property::SendAt,
            0x0072_6564_6e65 => Property::Sender,
            0x0074_4174_6e65 => Property::SentAt,
            0x0065_7a69 => Property::Size,
            0x7265_6472_4f74_726f => Property::SortOrder,
            0x7463_656a_6275 => Property::Subject,
            0x7374_7261_5062_7573 => Property::SubParts,
            _ => return None,
        },
        b't' => match hash {
            0x0079_646f_4274_7865 => Property::TextBody,
            0x6572_7574_616e_6769_5374_7865 => Property::TextSignature,
            0x0064_4964_6165_7268 => Property::ThreadId,
            0x0065_6e6f_7a65_6d69 => Property::Timezone,
            0x6f => Property::To,
            0x0065_7461_446f => Property::ToDate,
            0x736c_6961_6d45_6c61_746f => Property::TotalEmails,
            0x0073_6461_6572_6854_6c61_746f => Property::TotalThreads,
            0x0065_7079 => Property::Type,
            0x7365_7079 => Property::Types,
            _ => return None,
        },
        b'u' => match hash {
            0x0073_7574_6174_536f_646e => Property::UndoStatus,
            0x0073_6c69_616d_4564_6165_726e => Property::UnreadEmails,
            0x7364_6165_7268_5464_6165_726e => Property::UnreadThreads,
            0x6c72 => Property::Url,
            _ => return None,
        },
        b'v' => match hash {
            0x0065_646f_436e_6f69_7461_6369_6669_7265 => Property::VerificationCode,
            _ => return None,
        },
        _ => return None,
    })
}

fn parse_header_property(parser: &mut Parser) -> trc::Result<Property> {
    let hdr_start_pos = parser.pos;
    let mut has_next = false;

    while let Some(ch) = parser.next_unescaped()? {
        if ch == b':' {
            has_next = true;
            break;
        }
    }

    let mut all = false;
    let mut form = HeaderForm::Raw;
    let header = if parser.pos > hdr_start_pos + 1 {
        String::from_utf8_lossy(&parser.bytes[hdr_start_pos..parser.pos - 1]).into_owned()
    } else {
        return parser.invalid_property();
    };

    if has_next {
        match (parser.next_unescaped()?, parser.next_unescaped()?) {
            (Some(b'a'), Some(b's')) => {
                let mut hash = 0;
                let mut shift = 0;
                has_next = false;

                while let Some(ch) = parser.next_unescaped()? {
                    if ch != b':' {
                        if shift < 128 {
                            hash |= (ch as u128) << shift;
                            shift += 8;
                        } else {
                            return parser.invalid_property();
                        }
                    } else {
                        has_next = true;
                        break;
                    }
                }

                form = match hash {
                    0x7478_6554 => HeaderForm::Text,
                    0x0073_6573_7365_7264_6441 => HeaderForm::Addresses,
                    0x7365_7373_6572_6464_4164_6570_756f_7247 => HeaderForm::GroupedAddresses,
                    0x7364_4965_6761_7373_654d => HeaderForm::MessageIds,
                    0x6574_6144 => HeaderForm::Date,
                    0x734c_5255 => HeaderForm::URLs,
                    0x0077_6152 => HeaderForm::Raw,
                    _ => return parser.invalid_property(),
                };

                if has_next {
                    for ch in b"all" {
                        if Some(*ch) != parser.next_unescaped()? {
                            return parser.invalid_property();
                        }
                    }
                    if parser.next_unescaped()?.is_none() {
                        all = true;
                    } else {
                        return parser.invalid_property();
                    }
                }
            }
            (Some(b'a'), Some(b'l')) => {
                if let (Some(b'l'), None) = (parser.next_unescaped()?, parser.next_unescaped()?) {
                    all = true;
                } else {
                    return parser.invalid_property();
                }
            }
            _ => {
                return parser.invalid_property();
            }
        }
    }

    Ok(Property::Header(HeaderProperty { form, header, all }))
}

fn parse_sub_property(
    parser: &mut Parser,
    first_char: u8,
    parent_hash: u128,
) -> trc::Result<Property> {
    let mut hash = 0;
    let mut shift = 0;

    while let Some(ch) = parser.next_unescaped()? {
        if ch.is_ascii_alphanumeric() || ch == b'-' {
            if shift < 128 {
                hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                return parser.invalid_property();
            }
        } else {
            return parser.invalid_property();
        }
    }

    match (first_char, parent_hash, hash) {
        (b'd', 0x0061_7461, 0x7478_6554_7361) => Ok(Property::Data(DataProperty::AsText)),
        (b'd', 0x0061_7461, 0x3436_6573_6142_7361) => Ok(Property::Data(DataProperty::AsBase64)),
        (b'd', 0x0074_7365_6769, 0x0061_6873) => Ok(Property::Digest(DigestProperty::Sha)),
        (b'd', 0x0074_7365_6769, 0x0036_3532_2d61_6873) => {
            Ok(Property::Digest(DigestProperty::Sha256))
        }
        (b'd', 0x0074_7365_6769, 0x0032_3135_2d61_6873) => {
            Ok(Property::Digest(DigestProperty::Sha512))
        }
        _ => parser.invalid_property(),
    }
}

impl JsonObjectParser for ObjectProperty {
    fn parse(parser: &mut Parser) -> trc::Result<Self> {
        let mut first_char = 0;
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if ch.is_ascii_alphanumeric() {
                if first_char != 0 {
                    if shift < 128 {
                        hash |= (ch as u128) << shift;
                        shift += 8;
                    } else {
                        break;
                    }
                } else {
                    first_char = ch;
                }
            } else if ch == b':' && first_char == b'h' && hash == 0x0072_6564_6165 {
                return parse_header_property(parser).map(ObjectProperty);
            } else {
                return parser.invalid_property().map(ObjectProperty);
            }
        }

        Ok(ObjectProperty(match first_char {
            b'a' => match hash {
                0x7365_7373_6572_6464 => Property::Addresses,
                0x0068_7475 => Property::Auth,
                _ => parser.invalid_property()?,
            },
            b'b' => match hash {
                0x0064_4962_6f6c => Property::BlobId,
                _ => parser.invalid_property()?,
            },
            b'c' => match hash {
                0x7465_7372_6168 => Property::Charset,
                0x6469 => Property::Cid,
                _ => parser.invalid_property()?,
            },
            b'd' => match hash {
                0x6e6f_6974_6973_6f70_7369 => Property::Disposition,
                0x6465_7265_7669_6c65 => Property::Delivered,
                0x6465_7961_6c70_7369 => Property::Displayed,
                _ => parser.invalid_property()?,
            },
            b'e' => match hash {
                0x6c69_616d => Property::Email,
                _ => parser.invalid_property()?,
            },
            b'h' => match hash {
                0x7372_6564_6165 => Property::Headers,
                0x7469_6d69_4c64_7261 => Property::HardLimit,
                _ => parser.invalid_property()?,
            },
            b'i' => match hash {
                0x0065_6c62_6f72_5067_6e69_646f_636e_4573 => Property::IsEncodingProblem,
                0x6465_7461_636e_7572_5473 => Property::IsTruncated,
                _ => parser.invalid_property()?,
            },
            b'l' => match hash {
                0x0065_6761_7567_6e61 => Property::Language,
                0x006e_6f69_7461_636f => Property::Location,
                _ => parser.invalid_property()?,
            },
            b'm' => match hash {
                0x006d_6f72_466c_6961 => Property::MailFrom,
                0x0073_6d65_7449_6461_6552_7961 => Property::MayReadItems,
                0x736d_6574_4964_6441_7961 => Property::MayAddItems,
                0x0073_6d65_7449_6576_6f6d_6552_7961 => Property::MayRemoveItems,
                0x006e_6565_5374_6553_7961 => Property::MaySetSeen,
                0x0073_6472_6f77_7965_4b74_6553_7961 => Property::MaySetKeywords,
                0x0064_6c69_6843_6574_6165_7243_7961 => Property::MayCreateChild,
                0x656d_616e_6552_7961 => Property::MayRename,
                0x6574_656c_6544_7961 => Property::MayDelete,
                0x7469_6d62_7553_7961 => Property::MaySubmit,
                _ => parser.invalid_property()?,
            },
            b'n' => match hash {
                0x0065_6d61 => Property::Name,
                _ => parser.invalid_property()?,
            },
            b'p' => match hash {
                0x0064_4974_7261 => Property::PartId,
                0x0068_6436_3532 => Property::P256dh,
                0x0073_7265_7465_6d61_7261 => Property::Parameters,
                _ => parser.invalid_property()?,
            },
            b'r' => match hash {
                0x006f_5474_7063 => Property::RcptTo,
                0x0065_7079_5465_6372_756f_7365 => Property::ResourceType,
                _ => parser.invalid_property()?,
            },
            b's' => match hash {
                0x0065_7a69 => Property::Size,
                0x0073_7472_6150_6275 => Property::SubParts,
                0x796c_7065_5270_746d => Property::SmtpReply,
                0x7469_6d69_4c74_666f => Property::SoftLimit,
                0x6570_6f63 => Property::Scope,
                _ => parser.invalid_property()?,
            },
            b't' => match hash {
                0x0065_7079 => Property::Type,
                _ => parser.invalid_property()?,
            },
            b'u' => match hash {
                0x0064_6573 => Property::Used,
                _ => parser.invalid_property()?,
            },
            b'v' => match hash {
                0x6575_6c61 => Property::Value,
                _ => parser.invalid_property()?,
            },
            b'w' => match hash {
                0x7469_6d69_4c6e_7261 => Property::WarnLimit,
                _ => parser.invalid_property()?,
            },
            _ => parser.invalid_property()?,
        }))
    }
}

impl<'x> Parser<'x> {
    fn invalid_property(&mut self) -> trc::Result<Property> {
        if self.is_eof || self.skip_string() {
            Ok(Property::_T(
                String::from_utf8_lossy(self.bytes[self.pos_marker..self.pos - 1].as_ref())
                    .into_owned(),
            ))
        } else {
            Err(self.error_unterminated())
        }
    }
}

impl Property {
    pub fn parse(value: &str) -> Property {
        let mut first_char = 0;
        let mut hash = 0;
        let mut shift = 0;

        for &ch in value.as_bytes() {
            if ch.is_ascii_alphabetic() {
                if first_char != 0 {
                    if shift < 128 {
                        hash |= (ch as u128) << shift;
                        shift += 8;
                    } else {
                        return Property::_T(value.to_string());
                    }
                } else {
                    first_char = ch;
                }
            } else {
                return Property::_T(value.to_string());
            }
        }

        if let Some(property) = parse_property(first_char, hash) {
            property
        } else {
            Property::_T(value.to_string())
        }
    }

    pub fn as_rfc_header(&self) -> HeaderName<'static> {
        match self {
            Property::MessageId => HeaderName::MessageId,
            Property::InReplyTo => HeaderName::InReplyTo,
            Property::References => HeaderName::References,
            Property::Sender => HeaderName::Sender,
            Property::From => HeaderName::From,
            Property::To => HeaderName::To,
            Property::Cc => HeaderName::Cc,
            Property::Bcc => HeaderName::Bcc,
            Property::ReplyTo => HeaderName::ReplyTo,
            Property::Subject => HeaderName::Subject,
            Property::SentAt => HeaderName::Date,
            _ => unreachable!(),
        }
    }
}

impl Display for Property {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Property::Acl => write!(f, "acl"),
            Property::Aliases => write!(f, "aliases"),
            Property::Attachments => write!(f, "attachments"),
            Property::Bcc => write!(f, "bcc"),
            Property::BlobId => write!(f, "blobId"),
            Property::BodyStructure => write!(f, "bodyStructure"),
            Property::BodyValues => write!(f, "bodyValues"),
            Property::Capabilities => write!(f, "capabilities"),
            Property::Cc => write!(f, "cc"),
            Property::Charset => write!(f, "charset"),
            Property::Cid => write!(f, "cid"),
            Property::DeliveryStatus => write!(f, "deliveryStatus"),
            Property::Description => write!(f, "description"),
            Property::DeviceClientId => write!(f, "deviceClientId"),
            Property::Disposition => write!(f, "disposition"),
            Property::DsnBlobIds => write!(f, "dsnBlobIds"),
            Property::Email => write!(f, "email"),
            Property::EmailId => write!(f, "emailId"),
            Property::EmailIds => write!(f, "emailIds"),
            Property::Envelope => write!(f, "envelope"),
            Property::Expires => write!(f, "expires"),
            Property::From => write!(f, "from"),
            Property::FromDate => write!(f, "fromDate"),
            Property::HasAttachment => write!(f, "hasAttachment"),
            Property::Header(p) => write!(f, "{p}"),
            Property::Headers => write!(f, "headers"),
            Property::HtmlBody => write!(f, "htmlBody"),
            Property::HtmlSignature => write!(f, "htmlSignature"),
            Property::Id => write!(f, "id"),
            Property::IdentityId => write!(f, "identityId"),
            Property::InReplyTo => write!(f, "inReplyTo"),
            Property::IsActive => write!(f, "isActive"),
            Property::IsEnabled => write!(f, "isEnabled"),
            Property::IsSubscribed => write!(f, "isSubscribed"),
            Property::Keys => write!(f, "keys"),
            Property::Keywords => write!(f, "keywords"),
            Property::Language => write!(f, "language"),
            Property::Location => write!(f, "location"),
            Property::MailboxIds => write!(f, "mailboxIds"),
            Property::MayDelete => write!(f, "mayDelete"),
            Property::MdnBlobIds => write!(f, "mdnBlobIds"),
            Property::Members => write!(f, "members"),
            Property::MessageId => write!(f, "messageId"),
            Property::MyRights => write!(f, "myRights"),
            Property::Name => write!(f, "name"),
            Property::ParentId => write!(f, "parentId"),
            Property::PartId => write!(f, "partId"),
            Property::Picture => write!(f, "picture"),
            Property::Preview => write!(f, "preview"),
            Property::Quota => write!(f, "quota"),
            Property::ReceivedAt => write!(f, "receivedAt"),
            Property::References => write!(f, "references"),
            Property::ReplyTo => write!(f, "replyTo"),
            Property::Role => write!(f, "role"),
            Property::Secret => write!(f, "secret"),
            Property::SendAt => write!(f, "sendAt"),
            Property::Sender => write!(f, "sender"),
            Property::SentAt => write!(f, "sentAt"),
            Property::Size => write!(f, "size"),
            Property::SortOrder => write!(f, "sortOrder"),
            Property::Subject => write!(f, "subject"),
            Property::SubParts => write!(f, "subParts"),
            Property::TextBody => write!(f, "textBody"),
            Property::TextSignature => write!(f, "textSignature"),
            Property::ThreadId => write!(f, "threadId"),
            Property::Timezone => write!(f, "timezone"),
            Property::To => write!(f, "to"),
            Property::ToDate => write!(f, "toDate"),
            Property::TotalEmails => write!(f, "totalEmails"),
            Property::TotalThreads => write!(f, "totalThreads"),
            Property::Type => write!(f, "type"),
            Property::Types => write!(f, "types"),
            Property::UndoStatus => write!(f, "undoStatus"),
            Property::UnreadEmails => write!(f, "unreadEmails"),
            Property::UnreadThreads => write!(f, "unreadThreads"),
            Property::Url => write!(f, "url"),
            Property::VerificationCode => write!(f, "verificationCode"),
            Property::Parameters => write!(f, "parameters"),
            Property::Addresses => write!(f, "addresses"),
            Property::P256dh => write!(f, "p256dh"),
            Property::Auth => write!(f, "auth"),
            Property::Value => write!(f, "value"),
            Property::SmtpReply => write!(f, "smtpReply"),
            Property::Delivered => write!(f, "delivered"),
            Property::Displayed => write!(f, "displayed"),
            Property::MailFrom => write!(f, "mailFrom"),
            Property::RcptTo => write!(f, "rcptTo"),
            Property::IsEncodingProblem => write!(f, "isEncodingProblem"),
            Property::IsTruncated => write!(f, "isTruncated"),
            Property::MayReadItems => write!(f, "mayReadItems"),
            Property::MayAddItems => write!(f, "mayAddItems"),
            Property::MayRemoveItems => write!(f, "mayRemoveItems"),
            Property::MaySetSeen => write!(f, "maySetSeen"),
            Property::MaySetKeywords => write!(f, "maySetKeywords"),
            Property::MayCreateChild => write!(f, "mayCreateChild"),
            Property::MayRename => write!(f, "mayRename"),
            Property::MaySubmit => write!(f, "maySubmit"),
            Property::Data(data) => f.write_str(match data {
                DataProperty::AsText => "data:asText",
                DataProperty::AsBase64 => "data:asBase64",
                DataProperty::Default => "data",
            }),
            Property::Digest(digest) => f.write_str(match digest {
                DigestProperty::Sha => "digest:sha",
                DigestProperty::Sha256 => "digest:sha-256",
                DigestProperty::Sha512 => "digest:sha-512",
            }),
            Property::ResourceType => write!(f, "resourceType"),
            Property::Used => write!(f, "used"),
            Property::HardLimit => write!(f, "hardLimit"),
            Property::Scope => write!(f, "scope"),
            Property::WarnLimit => write!(f, "warnLimit"),
            Property::SoftLimit => write!(f, "softLimit"),
            Property::_T(s) => write!(f, "{s}"),
        }
    }
}

impl Display for SetProperty {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.property.fmt(f)
    }
}

impl Display for ObjectProperty {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoProperty for ObjectProperty {
    fn into_property(self) -> Property {
        self.0
    }
}

impl IntoProperty for String {
    fn into_property(self) -> Property {
        Property::_T(self)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HeaderProperty {
    pub form: HeaderForm,
    pub header: String,
    pub all: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HeaderForm {
    Raw,
    Text,
    Addresses,
    GroupedAddresses,
    MessageIds,
    Date,
    URLs,
}

impl Display for HeaderProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "header:{}", self.header)?;
        self.form.fmt(f)?;
        if self.all {
            write!(f, ":all")
        } else {
            Ok(())
        }
    }
}

impl Display for HeaderForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderForm::Raw => Ok(()),
            HeaderForm::Text => write!(f, ":asText"),
            HeaderForm::Addresses => write!(f, ":asAddresses"),
            HeaderForm::GroupedAddresses => write!(f, ":asGroupedAddresses"),
            HeaderForm::MessageIds => write!(f, ":asMessageIds"),
            HeaderForm::Date => write!(f, ":asDate"),
            HeaderForm::URLs => write!(f, ":asURLs"),
        }
    }
}

impl From<&Property> for u8 {
    fn from(value: &Property) -> Self {
        match value {
            Property::IsActive => 0,
            Property::IsEnabled => 1,
            Property::IsSubscribed => 2,
            Property::Keys => 3,
            Property::Keywords => 4,
            Property::Language => 5,
            Property::Location => 6,
            Property::MailboxIds => 7,
            Property::MayDelete => 8,
            Property::MdnBlobIds => 9,
            Property::Members => 10,
            Property::MessageId => 11,
            Property::MyRights => 12,
            Property::Name => 13,
            Property::ParentId => 14,
            Property::PartId => 15,
            Property::Picture => 16,
            Property::Preview => 17,
            Property::Quota => 18,
            Property::ReceivedAt => 19,
            Property::References => 20,
            Property::ReplyTo => 21,
            Property::Role => 22,
            Property::Secret => 23,
            Property::SendAt => 24,
            Property::Sender => 25,
            Property::SentAt => 26,
            Property::Size => 27,
            Property::SortOrder => 28,
            Property::Subject => 29,
            Property::SubParts => 30,
            Property::TextBody => 31,
            Property::TextSignature => 32,
            Property::ThreadId => 33,
            Property::Timezone => 34,
            Property::To => 35,
            Property::ToDate => 36,
            Property::TotalEmails => 37,
            Property::TotalThreads => 38,
            Property::Type => 39,
            Property::Types => 40,
            Property::UndoStatus => 41,
            Property::UnreadEmails => 42,
            Property::UnreadThreads => 43,
            Property::Url => 44,
            Property::VerificationCode => 45,
            Property::Parameters => 46,
            Property::Addresses => 47,
            Property::P256dh => 48,
            Property::Auth => 49,
            Property::Value => 50,
            Property::SmtpReply => 51,
            Property::Delivered => 52,
            Property::Displayed => 53,
            Property::MailFrom => 54,
            Property::RcptTo => 55,
            Property::IsEncodingProblem => 56,
            Property::IsTruncated => 57,
            Property::MayReadItems => 58,
            Property::MayAddItems => 59,
            Property::MayRemoveItems => 60,
            Property::MaySetSeen => 61,
            Property::MaySetKeywords => 62,
            Property::MayCreateChild => 63,
            Property::MayRename => 64,
            Property::MaySubmit => 65,
            Property::Acl => 66,
            Property::Aliases => 67,
            Property::Attachments => 68,
            Property::Bcc => 69,
            Property::BlobId => 70,
            Property::BodyStructure => 71,
            Property::BodyValues => 72,
            Property::Capabilities => 73,
            Property::Cc => 74,
            Property::Charset => 75,
            Property::Cid => 76,
            Property::DeliveryStatus => 77,
            Property::Description => 78,
            Property::DeviceClientId => 79,
            Property::Disposition => 80,
            Property::DsnBlobIds => 81,
            Property::Email => 82,
            Property::EmailId => 83,
            Property::EmailIds => 84,
            Property::Envelope => 85,
            Property::Expires => 86,
            Property::From => 87,
            Property::FromDate => 88,
            Property::HasAttachment => 89,
            Property::Header(_) => 90,
            Property::Headers => 91,
            Property::HtmlBody => 92,
            Property::HtmlSignature => 93,
            Property::Id => 94,
            Property::IdentityId => 95,
            Property::InReplyTo => 96,
            Property::_T(_) => 97,
            Property::ResourceType => 98,
            Property::Used => 99,
            Property::HardLimit => 100,
            Property::WarnLimit => 101,
            Property::SoftLimit => 102,
            Property::Scope => 103,
            Property::Digest(_) | Property::Data(_) => unreachable!("invalid property"),
        }
    }
}

impl From<Property> for u8 {
    fn from(value: Property) -> Self {
        (&value).into()
    }
}

impl Property {
    pub fn from_header(header: &HeaderName) -> Self {
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
}

impl SerializeInto for Property {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push(match self {
            Property::IsActive => 0,
            Property::IsEnabled => 1,
            Property::IsSubscribed => 2,
            Property::Keys => 3,
            Property::Keywords => 4,
            Property::Language => 5,
            Property::Location => 6,
            Property::MailboxIds => 7,
            Property::MayDelete => 8,
            Property::MdnBlobIds => 9,
            Property::Members => 10,
            Property::MessageId => 11,
            Property::MyRights => 12,
            Property::Name => 13,
            Property::ParentId => 14,
            Property::PartId => 15,
            Property::Picture => 16,
            Property::Preview => 17,
            Property::Quota => 18,
            Property::ReceivedAt => 19,
            Property::References => 20,
            Property::ReplyTo => 21,
            Property::Role => 22,
            Property::Secret => 23,
            Property::SendAt => 24,
            Property::Sender => 25,
            Property::SentAt => 26,
            Property::Size => 27,
            Property::SortOrder => 28,
            Property::Subject => 29,
            Property::SubParts => 30,
            Property::TextBody => 31,
            Property::TextSignature => 32,
            Property::ThreadId => 33,
            Property::Timezone => 34,
            Property::To => 35,
            Property::ToDate => 36,
            Property::TotalEmails => 37,
            Property::TotalThreads => 38,
            Property::Type => 39,
            Property::Types => 40,
            Property::UndoStatus => 41,
            Property::UnreadEmails => 42,
            Property::UnreadThreads => 43,
            Property::Url => 44,
            Property::VerificationCode => 45,
            Property::Parameters => 46,
            Property::Addresses => 47,
            Property::P256dh => 48,
            Property::Auth => 49,
            Property::Value => 50,
            Property::SmtpReply => 51,
            Property::Delivered => 52,
            Property::Displayed => 53,
            Property::MailFrom => 54,
            Property::RcptTo => 55,
            Property::IsEncodingProblem => 56,
            Property::IsTruncated => 57,
            Property::MayReadItems => 58,
            Property::MayAddItems => 59,
            Property::MayRemoveItems => 60,
            Property::MaySetSeen => 61,
            Property::MaySetKeywords => 62,
            Property::MayCreateChild => 63,
            Property::MayRename => 64,
            Property::MaySubmit => 65,
            Property::Acl => 66,
            Property::Aliases => 67,
            Property::Attachments => 68,
            Property::Bcc => 69,
            Property::BlobId => 70,
            Property::BodyStructure => 71,
            Property::BodyValues => 72,
            Property::Capabilities => 73,
            Property::Cc => 74,
            Property::Charset => 75,
            Property::Cid => 76,
            Property::DeliveryStatus => 77,
            Property::Description => 78,
            Property::DeviceClientId => 79,
            Property::Disposition => 80,
            Property::DsnBlobIds => 81,
            Property::Email => 82,
            Property::EmailId => 83,
            Property::EmailIds => 84,
            Property::Envelope => 85,
            Property::Expires => 86,
            Property::From => 87,
            Property::FromDate => 88,
            Property::HasAttachment => 89,
            Property::Header(_) => 90,
            Property::Headers => 91,
            Property::HtmlBody => 92,
            Property::HtmlSignature => 93,
            Property::Id => 94,
            Property::IdentityId => 95,
            Property::InReplyTo => 96,
            Property::_T(value) => {
                buf.push(97);
                value.serialize_into(buf);
                return;
            }
            Property::ResourceType => 98,
            Property::Used => 99,
            Property::HardLimit => 100,
            Property::WarnLimit => 101,
            Property::SoftLimit => 102,
            Property::Scope => 103,
            Property::Digest(_) | Property::Data(_) => {
                unreachable!("Property::Digest and Property::Data are not serializable")
            }
        });
    }
}

impl DeserializeFrom for Property {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            0 => Some(Property::IsActive),
            1 => Some(Property::IsEnabled),
            2 => Some(Property::IsSubscribed),
            3 => Some(Property::Keys),
            4 => Some(Property::Keywords),
            5 => Some(Property::Language),
            6 => Some(Property::Location),
            7 => Some(Property::MailboxIds),
            8 => Some(Property::MayDelete),
            9 => Some(Property::MdnBlobIds),
            10 => Some(Property::Members),
            11 => Some(Property::MessageId),
            12 => Some(Property::MyRights),
            13 => Some(Property::Name),
            14 => Some(Property::ParentId),
            15 => Some(Property::PartId),
            16 => Some(Property::Picture),
            17 => Some(Property::Preview),
            18 => Some(Property::Quota),
            19 => Some(Property::ReceivedAt),
            20 => Some(Property::References),
            21 => Some(Property::ReplyTo),
            22 => Some(Property::Role),
            23 => Some(Property::Secret),
            24 => Some(Property::SendAt),
            25 => Some(Property::Sender),
            26 => Some(Property::SentAt),
            27 => Some(Property::Size),
            28 => Some(Property::SortOrder),
            29 => Some(Property::Subject),
            30 => Some(Property::SubParts),
            31 => Some(Property::TextBody),
            32 => Some(Property::TextSignature),
            33 => Some(Property::ThreadId),
            34 => Some(Property::Timezone),
            35 => Some(Property::To),
            36 => Some(Property::ToDate),
            37 => Some(Property::TotalEmails),
            38 => Some(Property::TotalThreads),
            39 => Some(Property::Type),
            40 => Some(Property::Types),
            41 => Some(Property::UndoStatus),
            42 => Some(Property::UnreadEmails),
            43 => Some(Property::UnreadThreads),
            44 => Some(Property::Url),
            45 => Some(Property::VerificationCode),
            46 => Some(Property::Parameters),
            47 => Some(Property::Addresses),
            48 => Some(Property::P256dh),
            49 => Some(Property::Auth),
            50 => Some(Property::Value),
            51 => Some(Property::SmtpReply),
            52 => Some(Property::Delivered),
            53 => Some(Property::Displayed),
            54 => Some(Property::MailFrom),
            55 => Some(Property::RcptTo),
            56 => Some(Property::IsEncodingProblem),
            57 => Some(Property::IsTruncated),
            58 => Some(Property::MayReadItems),
            59 => Some(Property::MayAddItems),
            60 => Some(Property::MayRemoveItems),
            61 => Some(Property::MaySetSeen),
            62 => Some(Property::MaySetKeywords),
            63 => Some(Property::MayCreateChild),
            64 => Some(Property::MayRename),
            65 => Some(Property::MaySubmit),
            66 => Some(Property::Acl),
            67 => Some(Property::Aliases),
            68 => Some(Property::Attachments),
            69 => Some(Property::Bcc),
            70 => Some(Property::BlobId),
            71 => Some(Property::BodyStructure),
            72 => Some(Property::BodyValues),
            73 => Some(Property::Capabilities),
            74 => Some(Property::Cc),
            75 => Some(Property::Charset),
            76 => Some(Property::Cid),
            77 => Some(Property::DeliveryStatus),
            78 => Some(Property::Description),
            79 => Some(Property::DeviceClientId),
            80 => Some(Property::Disposition),
            81 => Some(Property::DsnBlobIds),
            82 => Some(Property::Email),
            83 => Some(Property::EmailId),
            84 => Some(Property::EmailIds),
            85 => Some(Property::Envelope),
            86 => Some(Property::Expires),
            87 => Some(Property::From),
            88 => Some(Property::FromDate),
            89 => Some(Property::HasAttachment),
            90 => Some(Property::Header(HeaderProperty {
                form: HeaderForm::Raw,
                header: String::new(),
                all: false,
            })), // Never serialized
            91 => Some(Property::Headers),
            92 => Some(Property::HtmlBody),
            93 => Some(Property::HtmlSignature),
            94 => Some(Property::Id),
            95 => Some(Property::IdentityId),
            96 => Some(Property::InReplyTo),
            97 => String::deserialize_from(bytes).map(Property::_T),
            98 => Some(Property::ResourceType),
            99 => Some(Property::Used),
            100 => Some(Property::HardLimit),
            101 => Some(Property::WarnLimit),
            102 => Some(Property::SoftLimit),
            103 => Some(Property::Scope),
            _ => None,
        }
    }
}

impl Serialize for Property {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl AsRef<Property> for Property {
    fn as_ref(&self) -> &Property {
        self
    }
}
