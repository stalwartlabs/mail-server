use std::fmt::{Display, Formatter};

use serde::Serialize;

use crate::parser::{json::Parser, Error, JsonObjectParser};

use super::{acl::Acl, id::Id, keyword::Keyword, value::Value};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
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
    _T(String),
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
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self> {
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
            } else if ch == b':' && first_char == b'h' && hash == 0x7265_6461_65 {
                return parse_header_property(parser);
            } else {
                return parser.invalid_property();
            }
        }

        parse_property(parser, first_char, hash)
    }
}

impl JsonObjectParser for SetProperty {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self> {
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
                    b':' if first_char == b'h' && hash == 0x7265_6461_65 && !is_ref => {
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

        let mut property = parse_property(parser, first_char, hash)?;
        let mut patch = Vec::new();

        if is_patch {
            match &property {
                Property::MailboxIds | Property::Members => match Id::parse(parser) {
                    Ok(id) => {
                        patch.push(Value::Id(id));
                    }
                    Err(Error::Method(_)) => {
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
                    Err(Error::Method(_)) => {
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
                                        patch.push(Value::Acl(acl));
                                    }
                                    Err(Error::Method(_)) => {
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

fn parse_property(
    parser: &mut Parser,
    first_char: u8,
    hash: u128,
) -> crate::parser::Result<Property> {
    Ok(match first_char {
        b'a' => match hash {
            0x6c63 => Property::Acl,
            0x7365_7361_696c => Property::Aliases,
            0x7374_6e65_6d68_6361_7474 => Property::Attachments,
            _ => parser.invalid_property()?,
        },
        b'b' => match hash {
            0x6363 => Property::Bcc,
            0x6449_626f_6c => Property::BlobId,
            0x6572_7574_6375_7274_5379_646f => Property::BodyStructure,
            0x7365_756c_6156_7964_6f => Property::BodyValues,
            _ => parser.invalid_property()?,
        },
        b'c' => match hash {
            0x7365_6974_696c_6962_6170_61 => Property::Capabilities,
            0x63 => Property::Cc,
            0x7465_7372_6168 => Property::Charset,
            0x6469 => Property::Cid,
            _ => parser.invalid_property()?,
        },
        b'd' => match hash {
            0x7375_7461_7453_7972_6576_696c_65 => Property::DeliveryStatus,
            0x6e6f_6974_7069_7263_7365 => Property::Description,
            0x6449_746e_6569_6c43_6563_6976_65 => Property::DeviceClientId,
            0x6e6f_6974_6973_6f70_7369 => Property::Disposition,
            0x7364_4962_6f6c_426e_73 => Property::DsnBlobIds,
            _ => parser.invalid_property()?,
        },
        b'e' => match hash {
            0x6c69_616d => Property::Email,
            0x6449_6c69_616d => Property::EmailId,
            0x7364_496c_6961_6d => Property::EmailIds,
            0x6570_6f6c_6576_6e => Property::Envelope,
            0x7365_7269_7078 => Property::Expires,
            _ => parser.invalid_property()?,
        },
        b'f' => match hash {
            0x6d6f_72 => Property::From,
            0x6574_6144_6d6f_72 => Property::FromDate,
            _ => parser.invalid_property()?,
        },
        b'h' => match hash {
            0x746e_656d_6863_6174_7441_7361 => Property::HasAttachment,
            0x7372_6564_6165 => Property::Headers,
            0x7964_6f42_6c6d_74 => Property::HtmlBody,
            0x6572_7574_616e_6769_536c_6d74 => Property::HtmlSignature,
            _ => parser.invalid_property()?,
        },
        b'i' => match hash {
            0x64 => Property::Id,
            0x0064_4979_7469_746e_6564 => Property::IdentityId,
            0x6f54_796c_7065_526e => Property::InReplyTo,
            0x6576_6974_6341_73 => Property::IsActive,
            0x6465_6c62_616e_4573 => Property::IsEnabled,
            0x6465_6269_7263_7362_7553_73 => Property::IsSubscribed,
            _ => parser.invalid_property()?,
        },
        b'k' => match hash {
            0x7379_65 => Property::Keys,
            0x7364_726f_7779_65 => Property::Keywords,
            _ => parser.invalid_property()?,
        },
        b'l' => match hash {
            0x6567_6175_676e_61 => Property::Language,
            0x6e6f_6974_6163_6f => Property::Location,
            _ => parser.invalid_property()?,
        },
        b'm' => match hash {
            0x7364_4978_6f62_6c69_61 => Property::MailboxIds,
            0x6574_656c_6544_7961 => Property::MayDelete,
            0x0073_6449_626f_6c42_6e64 => Property::MdnBlobIds,
            0x7372_6562_6d65 => Property::Members,
            0x6449_6567_6173_7365 => Property::MessageId,
            0x7374_6867_6952_79 => Property::MyRights,
            _ => parser.invalid_property()?,
        },
        b'n' => match hash {
            0x656d_61 => Property::Name,
            _ => parser.invalid_property()?,
        },
        b'p' => match hash {
            0x6449_746e_6572_61 => Property::ParentId,
            0x6449_7472_61 => Property::PartId,
            0x6572_7574_6369 => Property::Picture,
            0x7765_6976_6572 => Property::Preview,
            _ => parser.invalid_property()?,
        },
        b'q' => match hash {
            0x6174_6f75 => Property::Quota,
            _ => parser.invalid_property()?,
        },
        b'r' => match hash {
            0x7441_6465_7669_6563_65 => Property::ReceivedAt,
            0x7365_636e_6572_6566_65 => Property::References,
            0x6f54_796c_7065 => Property::ReplyTo,
            0x656c_6f => Property::Role,
            _ => parser.invalid_property()?,
        },
        b's' => match hash {
            0x7465_7263_65 => Property::Secret,
            0x7441_646e_65 => Property::SendAt,
            0x7265_646e_65 => Property::Sender,
            0x7441_746e_65 => Property::SentAt,
            0x657a_69 => Property::Size,
            0x7265_6472_4f74_726f => Property::SortOrder,
            0x7463_656a_6275 => Property::Subject,
            0x7374_7261_5062_7573 => Property::SubParts,
            _ => parser.invalid_property()?,
        },
        b't' => match hash {
            0x7964_6f42_7478_65 => Property::TextBody,
            0x6572_7574_616e_6769_5374_7865 => Property::TextSignature,
            0x6449_6461_6572_68 => Property::ThreadId,
            0x656e_6f7a_656d_69 => Property::Timezone,
            0x6f => Property::To,
            0x6574_6144_6f => Property::ToDate,
            0x736c_6961_6d45_6c61_746f => Property::TotalEmails,
            0x7364_6165_7268_546c_6174_6f => Property::TotalThreads,
            0x6570_79 => Property::Type,
            0x7365_7079 => Property::Types,
            _ => parser.invalid_property()?,
        },
        b'u' => match hash {
            0x7375_7461_7453_6f64_6e => Property::UndoStatus,
            0x736c_6961_6d45_6461_6572_6e => Property::UnreadEmails,
            0x7364_6165_7268_5464_6165_726e => Property::UnreadThreads,
            0x6c72 => Property::Url,
            _ => parser.invalid_property()?,
        },
        b'v' => match hash {
            0x6564_6f43_6e6f_6974_6163_6966_6972_65 => Property::VerificationCode,
            _ => parser.invalid_property()?,
        },
        _ => parser.invalid_property()?,
    })
}

fn parse_header_property(parser: &mut Parser) -> crate::parser::Result<Property> {
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
                    0x7365_7373_6572_6464_41 => HeaderForm::Addresses,
                    0x7365_7373_6572_6464_4164_6570_756f_7247 => HeaderForm::GroupedAddresses,
                    0x7364_4965_6761_7373_654d => HeaderForm::MessageIds,
                    0x6574_6144 => HeaderForm::Date,
                    0x734c_5255 => HeaderForm::URLs,
                    0x7761_52 => HeaderForm::Raw,
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

impl JsonObjectParser for ObjectProperty {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self> {
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
                        break;
                    }
                } else {
                    first_char = ch;
                }
            } else if ch == b':' && first_char == b'h' && hash == 0x7265_6461_65 {
                return parse_header_property(parser).map(ObjectProperty);
            } else {
                return parser.invalid_property().map(ObjectProperty);
            }
        }

        Ok(ObjectProperty(match first_char {
            b'a' => match hash {
                0x7365_7373_6572_6464 => Property::Addresses,
                0x6874_75 => Property::Auth,
                _ => parser.invalid_property()?,
            },
            b'b' => match hash {
                0x6449_626f_6c => Property::BlobId,
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
                _ => parser.invalid_property()?,
            },
            b'i' => match hash {
                0x656c_626f_7250_676e_6964_6f63_6e45_73 => Property::IsEncodingProblem,
                0x6465_7461_636e_7572_5473 => Property::IsTruncated,
                _ => parser.invalid_property()?,
            },
            b'l' => match hash {
                0x6567_6175_676e_61 => Property::Language,
                0x6e6f_6974_6163_6f => Property::Location,
                _ => parser.invalid_property()?,
            },
            b'm' => match hash {
                0x6d6f_7246_6c69_61 => Property::MailFrom,
                0x736d_6574_4964_6165_5279_61 => Property::MayReadItems,
                0x736d_6574_4964_6441_7961 => Property::MayAddItems,
                0x736d_6574_4965_766f_6d65_5279_61 => Property::MayRemoveItems,
                0x6e65_6553_7465_5379_61 => Property::MaySetSeen,
                0x7364_726f_7779_654b_7465_5379_61 => Property::MaySetKeywords,
                0x646c_6968_4365_7461_6572_4379_61 => Property::MayCreateChild,
                0x656d_616e_6552_7961 => Property::MayRename,
                0x6574_656c_6544_7961 => Property::MayDelete,
                0x7469_6d62_7553_7961 => Property::MaySubmit,
                _ => parser.invalid_property()?,
            },
            b'n' => match hash {
                0x656d_61 => Property::Name,
                _ => parser.invalid_property()?,
            },
            b'p' => match hash {
                0x6449_7472_61 => Property::PartId,
                0x0068_6436_3532 => Property::P256dh,
                0x7372_6574_656d_6172_61 => Property::Parameters,
                _ => parser.invalid_property()?,
            },
            b'r' => match hash {
                0x6f54_7470_63 => Property::RcptTo,
                _ => parser.invalid_property()?,
            },
            b's' => match hash {
                0x657a_69 => Property::Size,
                0x7374_7261_5062_75 => Property::SubParts,
                0x796c_7065_5270_746d => Property::SmtpReply,
                _ => parser.invalid_property()?,
            },
            b't' => match hash {
                0x6570_79 => Property::Type,
                _ => parser.invalid_property()?,
            },
            b'v' => match hash {
                0x6575_6c61 => Property::Value,
                _ => parser.invalid_property()?,
            },
            _ => parser.invalid_property()?,
        }))
    }
}

impl<'x> Parser<'x> {
    fn invalid_property(&mut self) -> crate::parser::Result<Property> {
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct HeaderProperty {
    pub form: HeaderForm,
    pub header: String,
    pub all: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize)]
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
