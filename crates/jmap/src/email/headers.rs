use jmap_proto::{
    object::Object,
    types::{
        property::{HeaderForm, Property},
        value::Value,
    },
};
use mail_parser::{parsers::MessageStream, Addr, HeaderName, HeaderValue, MessagePart, RfcHeader};

pub trait IntoForm {
    fn into_form(self, form: &HeaderForm) -> Value;
}

pub trait HeaderToValue {
    fn header_to_value(&self, property: &Property, raw_message: &[u8]) -> Value;
    fn headers_to_value(&self, raw_message: &[u8]) -> Value;
}

impl HeaderToValue for MessagePart<'_> {
    fn header_to_value(&self, property: &Property, raw_message: &[u8]) -> Value {
        let (header_name, form, all) = match property {
            Property::Header(header) => (
                HeaderName::parse(header.header.as_str())
                    .unwrap_or_else(|| HeaderName::Other(header.header.as_str().into())),
                header.form,
                header.all,
            ),
            Property::Sender => (
                HeaderName::Rfc(RfcHeader::Sender),
                HeaderForm::Addresses,
                false,
            ),
            Property::From => (
                HeaderName::Rfc(RfcHeader::From),
                HeaderForm::Addresses,
                false,
            ),
            Property::To => (HeaderName::Rfc(RfcHeader::To), HeaderForm::Addresses, false),
            Property::Cc => (HeaderName::Rfc(RfcHeader::Cc), HeaderForm::Addresses, false),
            Property::Bcc => (
                HeaderName::Rfc(RfcHeader::Bcc),
                HeaderForm::Addresses,
                false,
            ),
            Property::ReplyTo => (
                HeaderName::Rfc(RfcHeader::ReplyTo),
                HeaderForm::Addresses,
                false,
            ),
            Property::Subject => (HeaderName::Rfc(RfcHeader::Subject), HeaderForm::Text, false),
            Property::MessageId => (
                HeaderName::Rfc(RfcHeader::MessageId),
                HeaderForm::MessageIds,
                false,
            ),
            Property::InReplyTo => (
                HeaderName::Rfc(RfcHeader::InReplyTo),
                HeaderForm::MessageIds,
                false,
            ),
            Property::References => (
                HeaderName::Rfc(RfcHeader::References),
                HeaderForm::MessageIds,
                false,
            ),
            Property::SentAt => (HeaderName::Rfc(RfcHeader::Date), HeaderForm::Date, false),
            _ => return Value::Null,
        };

        let mut headers = Vec::new();

        match (&header_name, &form) {
            (HeaderName::Other(_), _) | (HeaderName::Rfc(_), HeaderForm::Raw) => {
                let header_name = header_name.as_str();
                for header in self.headers().iter().rev() {
                    if header.name.as_str().eq_ignore_ascii_case(header_name) {
                        let header_value = raw_message
                            .get(header.offset_start..header.offset_end)
                            .map_or(HeaderValue::Empty, |bytes| match form {
                                HeaderForm::Raw => {
                                    HeaderValue::Text(String::from_utf8_lossy(bytes.trim_end()))
                                }
                                HeaderForm::Text => MessageStream::new(bytes).parse_unstructured(),
                                HeaderForm::Addresses => MessageStream::new(bytes).parse_address(),
                                HeaderForm::GroupedAddresses => {
                                    MessageStream::new(bytes).parse_address()
                                }
                                HeaderForm::MessageIds => MessageStream::new(bytes).parse_id(),
                                HeaderForm::Date => MessageStream::new(bytes).parse_date(),
                                HeaderForm::URLs => MessageStream::new(bytes).parse_address(),
                            });
                        headers.push(header_value.into_form(&form));
                        if !all {
                            break;
                        }
                    }
                }
            }
            (HeaderName::Rfc(header_name), _) => {
                let header_name = header_name.as_str();
                for header in self.headers().iter().rev() {
                    if header.name.as_str().eq_ignore_ascii_case(header_name) {
                        headers.push(header.value.clone().into_form(&form));
                        if !all {
                            break;
                        }
                    }
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
        let mut headers = Vec::with_capacity(self.headers.len());
        for header in self.headers() {
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
            (
                HeaderValue::Address(Addr {
                    address: Some(addr),
                    ..
                }),
                HeaderForm::URLs,
            ) if addr.contains(':') => Value::List(vec![addr.into()]),
            (HeaderValue::AddressList(addrlist), HeaderForm::URLs) => Value::List(
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
            ),
            (HeaderValue::Address(addr), HeaderForm::Addresses) => Value::List(vec![addr.into()]),
            (HeaderValue::AddressList(addrlist), HeaderForm::Addresses) => addrlist.into(),
            (HeaderValue::Group(group), HeaderForm::Addresses) => group.addresses.into(),
            (HeaderValue::GroupList(grouplist), HeaderForm::Addresses) => Value::List(
                grouplist
                    .into_iter()
                    .flat_map(|group| group.addresses)
                    .filter_map(|addr| {
                        if addr.address.as_ref()?.contains('@') {
                            Some(addr.into())
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
            (HeaderValue::Address(addr), HeaderForm::GroupedAddresses) => {
                Value::List(vec![Object::with_capacity(2)
                    .with_property(Property::Name, Value::Null)
                    .with_property(Property::Addresses, Value::List(vec![addr.into()]))
                    .into()])
            }

            (HeaderValue::AddressList(addrlist), HeaderForm::GroupedAddresses) => {
                Value::List(vec![Object::with_capacity(2)
                    .with_property(Property::Name, Value::Null)
                    .with_property(Property::Addresses, addrlist)
                    .into()])
            }
            (HeaderValue::Group(group), HeaderForm::GroupedAddresses) => {
                Value::List(vec![group.into()])
            }
            (HeaderValue::GroupList(grouplist), HeaderForm::GroupedAddresses) => grouplist.into(),

            _ => Value::Null,
        }
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
