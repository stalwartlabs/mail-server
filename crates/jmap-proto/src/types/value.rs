/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use mail_parser::{Addr, DateTime, Group};
use serde::Serialize;
use utils::map::bitmap::Bitmap;

use crate::{
    object::Object,
    parser::{json::Parser, Ignore, JsonObjectParser, Token},
    request::reference::{MaybeReference, ResultReference},
};

use super::{
    acl::Acl,
    any_id::AnyId,
    blob::BlobId,
    date::UTCDate,
    id::Id,
    keyword::Keyword,
    property::{HeaderForm, IntoProperty, ObjectProperty, Property},
};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Text(String),
    UnsignedInt(u64),
    Bool(bool),
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    Keyword(Keyword),
    List(Vec<Value>),
    Object(Object<Value>),
    Acl(Vec<AclGrant>),
    Blob(Vec<u8>),
    #[default]
    Null,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct AclGrant {
    pub account_id: u32,
    pub grants: Bitmap<Acl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetValue {
    Value(Value),
    Patch(Vec<Value>),
    IdReference(MaybeReference<AnyId, String>),
    IdReferences(Vec<MaybeReference<AnyId, String>>),
    ResultReference(ResultReference),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybePatchValue {
    Value(Value),
    Patch(Vec<Value>),
}

#[derive(Debug, Clone)]
pub struct SetValueMap<T> {
    pub values: Vec<T>,
}

pub trait IntoValue: Eq {
    fn into_value(self) -> Value;
}

impl Value {
    pub fn parse<K: JsonObjectParser + IntoProperty, V: JsonObjectParser + IntoValue>(
        token: Token<V>,
        parser: &mut Parser<'_>,
    ) -> trc::Result<Self> {
        Ok(match token {
            Token::String(v) => v.into_value(),
            Token::DictStart => {
                let mut properties = Object::with_capacity(4);
                while let Some(key) = parser.next_dict_key::<K>()? {
                    let property = key.into_property();
                    let value = Value::from_property(parser, &property)?;
                    properties.append(property, value);
                }
                Value::Object(properties)
            }
            Token::ArrayStart => {
                let mut values = Vec::with_capacity(4);
                loop {
                    match parser.next_token::<V>()? {
                        Token::Comma => (),
                        Token::ArrayEnd => break,
                        token => {
                            values.push(Value::parse::<K, V>(token, parser)?);
                        }
                    }
                }
                Value::List(values)
            }
            Token::Integer(v) => Value::UnsignedInt(std::cmp::max(v, 0) as u64),
            Token::Float(v) => Value::UnsignedInt(if v > 0.0 { v as u64 } else { 0 }),
            Token::Boolean(v) => Value::Bool(v),
            Token::Null => Value::Null,
            token => return Err(token.error("", "value")),
        })
    }

    pub fn from_property(
        parser: &mut Parser<'_>,
        property: &Property,
    ) -> trc::Result<Self> {
        match &property {
            Property::BlobId => Ok(parser
                .next_token::<BlobId>()?
                .unwrap_string_or_null("")?
                .map(Value::BlobId)
                .unwrap_or(Value::Null)),
            Property::Size => Ok(parser
                .next_token::<String>()?
                .unwrap_uint_or_null("")?
                .map(Value::UnsignedInt)
                .unwrap_or(Value::Null)),
            Property::PartId
            | Property::Name
            | Property::Email
            | Property::Type
            | Property::Charset
            | Property::Cid
            | Property::Disposition
            | Property::Location
            | Property::Value
            | Property::SmtpReply
            | Property::P256dh
            | Property::Delivered
            | Property::Displayed
            | Property::Auth => Ok(parser
                .next_token::<String>()?
                .unwrap_string_or_null("")?
                .map(Value::Text)
                .unwrap_or(Value::Null)),

            Property::Header(h) => {
                if matches!(h.form, HeaderForm::Date) {
                    Value::parse::<ObjectProperty, UTCDate>(parser.next_token()?, parser)
                } else {
                    Value::parse::<ObjectProperty, String>(parser.next_token()?, parser)
                }
            }

            Property::Headers
            | Property::Addresses
            | Property::MailFrom
            | Property::RcptTo
            | Property::SubParts => {
                Value::parse::<ObjectProperty, String>(parser.next_token()?, parser)
            }
            Property::Language | Property::Parameters => {
                Value::parse::<String, String>(parser.next_token()?, parser)
            }

            Property::IsEncodingProblem
            | Property::IsTruncated
            | Property::MayReadItems
            | Property::MayAddItems
            | Property::MayRemoveItems
            | Property::MaySetSeen
            | Property::MaySetKeywords
            | Property::MayCreateChild
            | Property::MayRename
            | Property::MayDelete
            | Property::MaySubmit => Ok(parser
                .next_token::<String>()?
                .unwrap_bool_or_null("")?
                .map(Value::Bool)
                .unwrap_or(Value::Null)),
            _ => Value::parse::<ObjectProperty, String>(parser.next_token()?, parser),
        }
    }

    pub fn try_unwrap_id(self) -> Option<Id> {
        match self {
            Value::Id(id) => id.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_bool(self) -> Option<bool> {
        match self {
            Value::Bool(b) => b.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_keyword(self) -> Option<Keyword> {
        match self {
            Value::Keyword(k) => k.into(),
            _ => None,
        }
    }

    pub fn try_unwrap_string(self) -> Option<String> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn try_unwrap_object(self) -> Option<Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn try_unwrap_list(self) -> Option<Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn try_unwrap_date(self) -> Option<UTCDate> {
        match self {
            Value::Date(d) => Some(d),
            _ => None,
        }
    }

    pub fn try_unwrap_blob_id(self) -> Option<BlobId> {
        match self {
            Value::BlobId(b) => Some(b),
            _ => None,
        }
    }

    pub fn try_unwrap_uint(self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(u),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_id(&self) -> Option<&Id> {
        match self {
            Value::Id(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_blob_id(&self) -> Option<&BlobId> {
        match self {
            Value::BlobId(id) => Some(id),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Value>> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_acl(&self) -> Option<&Vec<AclGrant>> {
        match self {
            Value::Acl(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(*u),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_date(&self) -> Option<&UTCDate> {
        match self {
            Value::Date(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_obj_mut(&mut self) -> Option<&mut Object<Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn try_cast_uint(&self) -> Option<u64> {
        match self {
            Value::UnsignedInt(u) => Some(*u),
            Value::Id(id) => Some(id.id()),
            Value::Bool(b) => Some(*b as u64),
            _ => None,
        }
    }
}

impl<T: JsonObjectParser + Display + Eq> JsonObjectParser for SetValueMap<T> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut values = Vec::new();
        match parser.next_token::<Ignore>()? {
            Token::DictStart => {
                while let Some(value) = parser.next_dict_key()? {
                    if bool::parse(parser)? {
                        values.push(value);
                    }
                }
            }
            Token::Null => (),
            token => return Err(token.error("", &token.to_string())),
        }
        Ok(SetValueMap { values })
    }
}

impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::Text(self)
    }
}

impl IntoValue for Id {
    fn into_value(self) -> Value {
        Value::Id(self)
    }
}

impl IntoValue for UTCDate {
    fn into_value(self) -> Value {
        Value::Date(self)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Value::UnsignedInt(value as u64)
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::UnsignedInt(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Value::UnsignedInt(value as u64)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::Text(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::Text(value.to_string())
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Value::Bool(value)
    }
}

impl From<Keyword> for Value {
    fn from(value: Keyword) -> Self {
        Value::Keyword(value)
    }
}

impl From<Object<Value>> for Value {
    fn from(value: Object<Value>) -> Self {
        Value::Object(value)
    }
}

impl From<BlobId> for Value {
    fn from(value: BlobId) -> Self {
        Value::BlobId(value)
    }
}

impl From<Id> for Value {
    fn from(value: Id) -> Self {
        Value::Id(value)
    }
}

impl From<DateTime> for Value {
    fn from(date: DateTime) -> Self {
        Value::Date(UTCDate {
            year: date.year,
            month: date.month,
            day: date.day,
            hour: date.hour,
            minute: date.minute,
            second: date.second,
            tz_before_gmt: date.tz_before_gmt,
            tz_hour: date.tz_hour,
            tz_minute: date.tz_minute,
        })
    }
}

impl From<UTCDate> for Value {
    fn from(date: UTCDate) -> Self {
        Value::Date(date)
    }
}

impl From<Cow<'_, str>> for Value {
    fn from(value: Cow<'_, str>) -> Self {
        Value::Text(value.into_owned())
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(value: Vec<T>) -> Self {
        Value::List(value.into_iter().map(|v| v.into()).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => value.into(),
            None => Value::Null,
        }
    }
}

impl From<Addr<'_>> for Value {
    fn from(value: Addr<'_>) -> Self {
        Value::Object(
            Object::with_capacity(2)
                .with_property(Property::Name, value.name)
                .with_property(Property::Email, value.address.unwrap_or_default()),
        )
    }
}

impl From<Group<'_>> for Value {
    fn from(group: Group<'_>) -> Self {
        Value::Object(
            Object::with_capacity(2)
                .with_property(Property::Name, group.name)
                .with_property(
                    Property::Addresses,
                    Value::List(
                        group
                            .addresses
                            .into_iter()
                            .map(Value::from)
                            .collect::<Vec<Value>>(),
                    ),
                ),
        )
    }
}
