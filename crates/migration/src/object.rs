/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{
    blob::BlobId,
    date::UTCDate,
    id::Id,
    keyword::*,
    property::{HeaderForm, HeaderProperty, Property},
    value::{AclGrant, Value},
};
use std::slice::Iter;
use store::{Deserialize, U64_LEN};
use utils::{
    codec::leb128::Leb128Iterator,
    map::{bitmap::Bitmap, vec_map::VecMap},
};

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Object<T> {
    pub properties: VecMap<Property, T>,
}

impl Object<Value> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            properties: VecMap::with_capacity(capacity),
        }
    }

    pub fn set(&mut self, property: Property, value: impl Into<Value>) -> bool {
        self.properties.set(property, value.into())
    }

    pub fn append(&mut self, property: Property, value: impl Into<Value>) {
        self.properties.append(property, value.into());
    }

    pub fn with_property(mut self, property: Property, value: impl Into<Value>) -> Self {
        self.properties.append(property, value.into());
        self
    }

    pub fn remove(&mut self, property: &Property) -> Value {
        self.properties.remove(property).unwrap_or(Value::Null)
    }

    pub fn get(&self, property: &Property) -> &Value {
        self.properties.get(property).unwrap_or(&Value::Null)
    }
}

const TEXT: u8 = 0;
const UNSIGNED_INT: u8 = 1;
const BOOL_TRUE: u8 = 2;
const BOOL_FALSE: u8 = 3;
const ID: u8 = 4;
const DATE: u8 = 5;
const BLOB_ID: u8 = 6;
const BLOB: u8 = 7;
const KEYWORD: u8 = 8;
const LIST: u8 = 9;
const OBJECT: u8 = 10;
const ACL: u8 = 11;
const NULL: u8 = 12;

pub trait DeserializeFrom: Sized {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self>;
}

impl Deserialize for Object<Value> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Object::deserialize_from(&mut bytes.iter()).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

impl DeserializeFrom for AclGrant {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let account_id = bytes.next_leb128()?;
        let mut grants = [0u8; U64_LEN];
        for byte in grants.iter_mut() {
            *byte = *bytes.next()?;
        }

        Some(Self {
            account_id,
            grants: Bitmap::from(u64::from_be_bytes(grants)),
        })
    }
}

impl DeserializeFrom for Object<Value> {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Object<Value>> {
        let len = bytes.next_leb128()?;
        let mut properties = VecMap::with_capacity(len);
        for _ in 0..len {
            let key = Property::deserialize_from(bytes)?;
            let value = Value::deserialize_from(bytes)?;
            properties.append(key, value);
        }
        Some(Object { properties })
    }
}

impl DeserializeFrom for Value {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            TEXT => Some(Value::Text(String::deserialize_from(bytes)?)),
            UNSIGNED_INT => Some(Value::UnsignedInt(bytes.next_leb128()?)),
            BOOL_TRUE => Some(Value::Bool(true)),
            BOOL_FALSE => Some(Value::Bool(false)),
            ID => Some(Value::Id(Id::new(bytes.next_leb128()?))),
            DATE => Some(Value::Date(UTCDate::from_timestamp(
                bytes.next_leb128::<u64>()? as i64,
            ))),
            BLOB_ID => Some(Value::BlobId(BlobId::deserialize_from(bytes)?)),
            KEYWORD => Some(Value::Keyword(Keyword::deserialize_from(bytes)?)),
            LIST => {
                let len = bytes.next_leb128()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(Value::deserialize_from(bytes)?);
                }
                Some(Value::List(items))
            }
            OBJECT => Some(Value::Object(jmap_proto::types::value::Object(
                Object::deserialize_from(bytes)?.properties,
            ))),
            BLOB => Some(Value::Blob(Vec::deserialize_from(bytes)?)),
            ACL => {
                let len = bytes.next_leb128()?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(AclGrant::deserialize_from(bytes)?);
                }
                Some(Value::Acl(items))
            }
            NULL => Some(Value::Null),
            _ => None,
        }
    }
}

impl DeserializeFrom for u32 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for u64 {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        bytes.next_leb128()
    }
}

impl DeserializeFrom for String {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        <Vec<u8>>::deserialize_from(bytes).and_then(|s| String::from_utf8(s).ok())
    }
}

impl DeserializeFrom for Vec<u8> {
    fn deserialize_from(bytes: &mut Iter<'_, u8>) -> Option<Self> {
        let len: usize = bytes.next_leb128()?;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(*bytes.next()?);
        }
        buf.into()
    }
}

impl DeserializeFrom for BlobId {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        BlobId::from_iter(bytes)
    }
}

impl DeserializeFrom for Keyword {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match bytes.next_leb128::<usize>()? {
            SEEN => Some(Keyword::Seen),
            DRAFT => Some(Keyword::Draft),
            FLAGGED => Some(Keyword::Flagged),
            ANSWERED => Some(Keyword::Answered),
            RECENT => Some(Keyword::Recent),
            IMPORTANT => Some(Keyword::Important),
            PHISHING => Some(Keyword::Phishing),
            JUNK => Some(Keyword::Junk),
            NOTJUNK => Some(Keyword::NotJunk),
            DELETED => Some(Keyword::Deleted),
            FORWARDED => Some(Keyword::Forwarded),
            MDN_SENT => Some(Keyword::MdnSent),
            other => {
                let len = other - OTHER;
                let mut keyword = Vec::with_capacity(len);
                for _ in 0..len {
                    keyword.push(*bytes.next()?);
                }
                Some(Keyword::Other(String::from_utf8(keyword).ok()?))
            }
        }
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

pub trait FromLegacy {
    fn from_legacy(legacy: Object<Value>) -> Self;
}

pub trait TryFromLegacy: Sized {
    fn try_from_legacy(legacy: Object<Value>) -> Option<Self>;
}
