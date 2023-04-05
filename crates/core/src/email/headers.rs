use mail_parser::{Addr, HeaderValue};
use protocol::{
    object::Object,
    types::{
        property::{HeaderForm, Property},
        value::Value,
    },
};

pub trait IntoForm {
    fn into_form(self, form: &HeaderForm) -> Value;
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
                    .map(Into::into)
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
