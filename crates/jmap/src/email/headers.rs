/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use jmap_proto::{
    object::Object,
    types::{
        property::{HeaderForm, HeaderProperty, Property},
        value::Value,
    },
};
use mail_builder::{
    headers::{
        address::{Address, EmailAddress, GroupedAddresses},
        date::Date,
        message_id::MessageId,
        raw::Raw,
        text::Text,
        url::URL,
    },
    MessageBuilder,
};
use mail_parser::{parsers::MessageStream, Addr, Header, HeaderName, HeaderValue};

pub trait IntoForm {
    fn into_form(self, form: &HeaderForm) -> Value;
}

pub trait HeaderToValue {
    fn header_to_value(&self, property: &Property, raw_message: &[u8]) -> Value;
    fn headers_to_value(&self, raw_message: &[u8]) -> Value;
}

pub trait ValueToHeader<'x> {
    fn try_into_grouped_addresses(self) -> Option<GroupedAddresses<'x>>;
    fn try_into_address_list(self) -> Option<Vec<Address<'x>>>;
    fn try_into_address(self) -> Option<EmailAddress<'x>>;
}

pub trait BuildHeader: Sized {
    fn build_header(self, header: HeaderProperty, value: Value) -> Result<Self, HeaderProperty>;
}

impl HeaderToValue for Vec<Header<'_>> {
    fn header_to_value(&self, property: &Property, raw_message: &[u8]) -> Value {
        let (header_name, form, all) = match property {
            Property::Header(header) => (
                HeaderName::parse(header.header.as_str())
                    .unwrap_or_else(|| HeaderName::Other(header.header.as_str().into())),
                header.form,
                header.all,
            ),
            Property::Sender => (HeaderName::Sender, HeaderForm::Addresses, false),
            Property::From => (HeaderName::From, HeaderForm::Addresses, false),
            Property::To => (HeaderName::To, HeaderForm::Addresses, false),
            Property::Cc => (HeaderName::Cc, HeaderForm::Addresses, false),
            Property::Bcc => (HeaderName::Bcc, HeaderForm::Addresses, false),
            Property::ReplyTo => (HeaderName::ReplyTo, HeaderForm::Addresses, false),
            Property::Subject => (HeaderName::Subject, HeaderForm::Text, false),
            Property::MessageId => (HeaderName::MessageId, HeaderForm::MessageIds, false),
            Property::InReplyTo => (HeaderName::InReplyTo, HeaderForm::MessageIds, false),
            Property::References => (HeaderName::References, HeaderForm::MessageIds, false),
            Property::SentAt => (HeaderName::Date, HeaderForm::Date, false),
            _ => return Value::Null,
        };

        let is_raw = matches!(form, HeaderForm::Raw) || matches!(header_name, HeaderName::Other(_));
        let mut headers = Vec::new();
        let header_name = header_name.as_str();
        for header in self.iter().rev() {
            if header.name.as_str().eq_ignore_ascii_case(header_name) {
                let header_value = if is_raw || matches!(header.value, HeaderValue::Empty) {
                    raw_message
                        .get(header.offset_start..header.offset_end)
                        .map_or(HeaderValue::Empty, |bytes| match form {
                            HeaderForm::Raw => {
                                HeaderValue::Text(String::from_utf8_lossy(bytes.trim_end()))
                            }
                            HeaderForm::Text => MessageStream::new(bytes).parse_unstructured(),
                            HeaderForm::Addresses
                            | HeaderForm::GroupedAddresses
                            | HeaderForm::URLs => MessageStream::new(bytes).parse_address(),
                            HeaderForm::MessageIds => MessageStream::new(bytes).parse_id(),
                            HeaderForm::Date => MessageStream::new(bytes).parse_date(),
                        })
                } else {
                    header.value.clone()
                };
                headers.push(header_value.into_form(&form));
                if !all {
                    break;
                }
            }
        }

        if !all {
            headers.pop().unwrap_or_default()
        } else {
            if headers.len() > 1 {
                headers.reverse();
            }
            Value::List(headers)
        }
    }

    fn headers_to_value(&self, raw_message: &[u8]) -> Value {
        let mut headers = Vec::with_capacity(self.len());
        for header in self.iter() {
            headers.push(Value::Object(
                Object::with_capacity(2)
                    .with_property(Property::Name, header.name().to_string())
                    .with_property(
                        Property::Value,
                        String::from_utf8_lossy(
                            raw_message
                                .get(header.offset_start..header.offset_end)
                                .unwrap_or_default()
                                .trim_end(),
                        )
                        .into_owned(),
                    ),
            ));
        }
        headers.into()
    }
}

impl IntoForm for HeaderValue<'_> {
    fn into_form(self, form: &HeaderForm) -> Value {
        match (self, form) {
            (HeaderValue::Text(text), HeaderForm::Raw | HeaderForm::Text) => text.into(),
            (HeaderValue::TextList(texts), HeaderForm::Raw | HeaderForm::Text) => {
                texts.join(", ").into()
            }
            (HeaderValue::Text(text), HeaderForm::MessageIds) => Value::List(vec![text.into()]),
            (HeaderValue::TextList(texts), HeaderForm::MessageIds) => texts.into(),
            (HeaderValue::DateTime(datetime), HeaderForm::Date) => datetime.into(),
            (HeaderValue::Address(mail_parser::Address::List(addrlist)), HeaderForm::URLs) => {
                Value::List(
                    addrlist
                        .into_iter()
                        .filter_map(|addr| match addr {
                            Addr {
                                address: Some(addr),
                                ..
                            } if addr.contains(':') => Some(addr.into()),
                            _ => None,
                        })
                        .collect(),
                )
            }
            (HeaderValue::Address(mail_parser::Address::List(addrlist)), HeaderForm::Addresses) => {
                addrlist.into()
            }
            (
                HeaderValue::Address(mail_parser::Address::Group(grouplist)),
                HeaderForm::Addresses,
            ) => Value::List(
                grouplist
                    .into_iter()
                    .flat_map(|group| group.addresses)
                    .map(Value::from)
                    .collect(),
            ),
            (
                HeaderValue::Address(mail_parser::Address::List(addrlist)),
                HeaderForm::GroupedAddresses,
            ) => Value::List(vec![Object::with_capacity(2)
                .with_property(Property::Name, Value::Null)
                .with_property(Property::Addresses, addrlist)
                .into()]),
            (
                HeaderValue::Address(mail_parser::Address::Group(grouplist)),
                HeaderForm::GroupedAddresses,
            ) => grouplist.into(),

            _ => Value::Null,
        }
    }
}

impl<'x> ValueToHeader<'x> for Value {
    fn try_into_grouped_addresses(self) -> Option<GroupedAddresses<'x>> {
        let mut obj = self.try_unwrap_object()?;
        Some(GroupedAddresses {
            name: obj
                .properties
                .remove(&Property::Name)
                .and_then(|n| n.try_unwrap_string())
                .map(|n| n.into()),
            addresses: obj
                .properties
                .remove(&Property::Addresses)?
                .try_into_address_list()?,
        })
    }

    fn try_into_address_list(self) -> Option<Vec<Address<'x>>> {
        let list = self.try_unwrap_list()?;
        let mut addresses = Vec::with_capacity(list.len());
        for value in list {
            addresses.push(Address::Address(value.try_into_address()?));
        }
        Some(addresses)
    }

    fn try_into_address(self) -> Option<EmailAddress<'x>> {
        let mut obj = self.try_unwrap_object()?;
        Some(EmailAddress {
            name: obj
                .properties
                .remove(&Property::Name)
                .and_then(|n| n.try_unwrap_string())
                .map(|n| n.into()),
            email: obj
                .properties
                .remove(&Property::Email)?
                .try_unwrap_string()?
                .into(),
        })
    }
}

impl BuildHeader for MessageBuilder<'_> {
    fn build_header(self, header: HeaderProperty, value: Value) -> Result<Self, HeaderProperty> {
        Ok(match (&header.form, header.all, value) {
            (HeaderForm::Raw, false, Value::Text(value)) => {
                self.header(header.header, Raw::from(value))
            }
            (HeaderForm::Raw, true, Value::List(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Raw::from(v.try_unwrap_string()?).into()),
            ),
            (HeaderForm::Date, false, Value::Date(value)) => {
                self.header(header.header, Date::new(value.timestamp()))
            }
            (HeaderForm::Date, true, Value::List(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Date::new(v.try_unwrap_date()?.timestamp()).into()),
            ),
            (HeaderForm::Text, false, Value::Text(value)) => {
                self.header(header.header, Text::from(value))
            }
            (HeaderForm::Text, true, Value::List(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Text::from(v.try_unwrap_string()?).into()),
            ),
            (HeaderForm::URLs, false, Value::List(value)) => self.header(
                header.header,
                URL {
                    url: value
                        .into_iter()
                        .filter_map(|v| Cow::from(v.try_unwrap_string()?).into())
                        .collect(),
                },
            ),
            (HeaderForm::URLs, true, Value::List(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|value| {
                    URL {
                        url: value
                            .try_unwrap_list()?
                            .into_iter()
                            .filter_map(|v| Cow::from(v.try_unwrap_string()?).into())
                            .collect(),
                    }
                    .into()
                }),
            ),
            (HeaderForm::MessageIds, false, Value::List(value)) => self.header(
                header.header,
                MessageId {
                    id: value
                        .into_iter()
                        .filter_map(|v| Cow::from(v.try_unwrap_string()?).into())
                        .collect(),
                },
            ),
            (HeaderForm::MessageIds, true, Value::List(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|value| {
                    MessageId {
                        id: value
                            .try_unwrap_list()?
                            .into_iter()
                            .filter_map(|v| Cow::from(v.try_unwrap_string()?).into())
                            .collect(),
                    }
                    .into()
                }),
            ),
            (HeaderForm::Addresses, false, Value::List(value)) => self.header(
                header.header,
                Address::new_list(
                    value
                        .into_iter()
                        .filter_map(|v| Address::Address(v.try_into_address()?).into())
                        .collect(),
                ),
            ),
            (HeaderForm::Addresses, true, Value::List(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Address::new_list(v.try_into_address_list()?).into()),
            ),
            (HeaderForm::GroupedAddresses, false, Value::List(value)) => self.header(
                header.header,
                Address::new_list(
                    value
                        .into_iter()
                        .filter_map(|v| Address::Group(v.try_into_grouped_addresses()?).into())
                        .collect(),
                ),
            ),
            (HeaderForm::GroupedAddresses, true, Value::List(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|v| {
                    Address::new_list(
                        v.try_unwrap_list()?
                            .into_iter()
                            .filter_map(|v| Address::Group(v.try_into_grouped_addresses()?).into())
                            .collect::<Vec<_>>(),
                    )
                    .into()
                }),
            ),
            _ => {
                return Err(header);
            }
        })
    }
}

trait ByteTrim {
    fn trim_end(&self) -> Self;
}

impl ByteTrim for &[u8] {
    fn trim_end(&self) -> Self {
        let mut end = self.len();
        while end > 0 && self[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        &self[..end]
    }
}
