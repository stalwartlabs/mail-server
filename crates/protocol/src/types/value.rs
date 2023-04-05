use std::{borrow::Cow, fmt::Display};

use mail_parser::{Addr, DateTime, Group};
use serde::Serialize;

use crate::{
    object::Object,
    parser::{json::Parser, Ignore, JsonObjectParser, Token},
    request::reference::ResultReference,
};

use super::{
    acl::Acl,
    blob::BlobId,
    date::UTCDate,
    id::Id,
    keyword::Keyword,
    property::{HeaderForm, IntoProperty, ObjectProperty, Property},
    type_state::TypeState,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Value {
    Text(String),
    UnsignedInt(u64),
    Bool(bool),
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    Keyword(Keyword),
    TypeState(TypeState),
    Acl(Acl),
    List(Vec<Value>),
    Object(Object<Value>),
    Null,
}

#[derive(Debug, Clone)]
pub enum SetValue {
    Value(Value),
    Patch(Vec<Value>),
    ResultReference(ResultReference),
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
        parser: &mut Parser<'_>,
    ) -> crate::parser::Result<Self> {
        Ok(match parser.next_token::<V>()? {
            Token::String(v) => v.into_value(),
            Token::DictStart => {
                let mut properties = Object::with_capacity(4);
                while {
                    let property = parser.next_dict_key::<K>()?.into_property();
                    let value = Value::from_property(parser, &property)?;
                    properties.append(property, value);
                    !parser.is_dict_end()?
                } {}
                Value::Object(properties)
            }
            Token::ArrayStart => {
                let mut values = Vec::with_capacity(4);
                while {
                    values.push(Value::parse::<K, V>(parser)?);
                    !parser.is_array_end()?
                } {}
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
    ) -> crate::parser::Result<Self> {
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
                    Value::parse::<ObjectProperty, UTCDate>(parser)
                } else {
                    Value::parse::<ObjectProperty, String>(parser)
                }
            }

            Property::Headers
            | Property::Addresses
            | Property::MailFrom
            | Property::RcptTo
            | Property::SubParts => Value::parse::<ObjectProperty, String>(parser),
            Property::Language | Property::Parameters => Value::parse::<String, String>(parser),

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
            _ => Value::parse::<String, String>(parser),
        }
    }
}

impl<T: JsonObjectParser + Display + Eq> JsonObjectParser for SetValueMap<T> {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut values = Vec::new();
        match parser.next_token::<Ignore>()? {
            Token::DictStart => {
                parser.next_token::<Ignore>()?.assert(Token::DictStart)?;
                while {
                    let value = parser.next_dict_key::<T>()?;
                    if bool::parse(parser)? {
                        values.push(value);
                    }
                    !parser.is_dict_end()?
                } {}
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

impl IntoValue for Acl {
    fn into_value(self) -> Value {
        Value::Acl(self)
    }
}

impl IntoValue for TypeState {
    fn into_value(self) -> Value {
        Value::TypeState(self)
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
                .with_property(Property::Addresses, group.addresses),
        )
    }
}
