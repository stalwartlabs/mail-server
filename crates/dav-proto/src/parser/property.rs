/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::PartialDateTime,
    icalendar::{ICalendar, ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::{VCardParameterName, VCardProperty},
    Entry, Parser,
};
use mail_parser::DateTime;

use crate::schema::{
    property::{
        CalDavProperty, CalDavPropertyName, CalendarData, CardDavProperty, CardDavPropertyName,
        Comp, DavProperty, DavValue, PrincipalProperty, ResourceType, TimeRange, WebDavProperty,
    },
    request::{DavPropertyValue, DeadProperty, VCardPropertyWithGroup},
    response::List,
    Attribute, AttributeValue, Element, NamedElement, Namespace,
};

use super::{tokenizer::Tokenizer, DavParser, RawElement, Token, XmlValueParser};

impl Tokenizer<'_> {
    pub(crate) fn collect_properties(
        &mut self,
        mut elements: Vec<DavProperty>,
    ) -> crate::parser::Result<Vec<DavProperty>> {
        loop {
            match self.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::CalendarData,
                        },
                    ..
                } => {
                    elements.push(DavProperty::CalDav(CalDavProperty::CalendarData(
                        self.collect_calendar_data()?,
                    )));
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CardDav,
                            element: Element::AddressData,
                        },
                    ..
                } => {
                    elements.push(DavProperty::CardDav(CardDavProperty::AddressData(
                        self.collect_address_data()?,
                    )));
                }
                Token::ElementStart { name, .. } => {
                    if let Some(property) = DavProperty::from_element(name) {
                        elements.push(property);
                    }
                    self.expect_element_end()?;
                }
                Token::ElementEnd => {
                    break;
                }
                Token::UnknownElement(name) => {
                    elements.push(DavProperty::DeadProperty((&name).into()));
                    self.expect_element_end()?;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(elements)
    }

    pub(crate) fn collect_calendar_data(&mut self) -> crate::parser::Result<CalendarData> {
        let mut depth = 1;
        let mut data = CalendarData {
            properties: Vec::with_capacity(4),
            expand: None,
            limit_recurrence: None,
            limit_freebusy: None,
        };
        let mut components: Vec<ICalendarComponentType> = Vec::new();

        loop {
            match self.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::Allcomp,
                        },
                    ..
                } => {
                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::Allprop,
                        },
                    ..
                } => {
                    if let Some(component) = components.last().cloned() {
                        data.properties.push(CalDavPropertyName {
                            component: Some(component),
                            name: None,
                            no_value: false,
                        });
                    }
                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::Comp,
                        },
                    raw,
                } => {
                    depth += 1;

                    for attribute in raw.attributes::<ICalendarComponentType>() {
                        if let Attribute::Name(name) = attribute? {
                            components.push(name);
                        }
                    }
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::Prop,
                        },
                    raw,
                } => {
                    let mut name = None;
                    let mut no_value = false;

                    for attribute in raw.attributes::<ICalendarProperty>() {
                        match attribute? {
                            Attribute::Name(name_) => {
                                name = Some(name_);
                            }
                            Attribute::NoValue(no_value_) => {
                                no_value = no_value_;
                            }
                            _ => {}
                        }
                    }

                    if let Some(name) = name {
                        data.properties.push(CalDavPropertyName {
                            component: components.last().cloned(),
                            name: Some(name),
                            no_value,
                        });
                    }

                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::Expand,
                        },
                    raw,
                } => {
                    data.expand = TimeRange::from_raw(&raw)?;
                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::LimitRecurrenceSet,
                        },
                    raw,
                } => {
                    data.limit_recurrence = TimeRange::from_raw(&raw)?;
                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CalDav,
                            element: Element::LimitFreebusySet,
                        },
                    raw,
                } => {
                    data.limit_freebusy = TimeRange::from_raw(&raw)?;
                    self.expect_element_end()?;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    if let Some(last_component) = components.pop() {
                        if last_component != ICalendarComponentType::VCalendar
                            && !matches!(data.properties.last(), Some(CalDavPropertyName { component: Some(component), .. }) if component == &last_component)
                        {
                            data.properties.push(CalDavPropertyName {
                                component: Some(last_component),
                                name: None,
                                no_value: false,
                            });
                        }
                    }
                }
                Token::Eof => {
                    break;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(data)
    }

    pub(crate) fn collect_address_data(
        &mut self,
    ) -> crate::parser::Result<Vec<CardDavPropertyName>> {
        let mut items = Vec::with_capacity(4);
        loop {
            match self.token()? {
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CardDav,
                            element: Element::Allprop,
                        },
                    ..
                } => {
                    self.expect_element_end()?;
                }
                Token::ElementStart {
                    name:
                        NamedElement {
                            ns: Namespace::CardDav,
                            element: Element::Prop,
                        },
                    raw,
                } => {
                    let mut name = None;
                    let mut group = None;
                    let mut no_value = false;

                    for attribute in raw.attributes::<VCardPropertyWithGroup>() {
                        match attribute? {
                            Attribute::Name(name_) => {
                                name = Some(name_.name);
                                group = name_.group;
                            }
                            Attribute::NoValue(no_value_) => {
                                no_value = no_value_;
                            }
                            _ => {}
                        }
                    }

                    if let Some(name) = name {
                        items.push(CardDavPropertyName {
                            name,
                            group,
                            no_value,
                        });
                    }

                    self.expect_element_end()?;
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(items)
    }
}

impl Tokenizer<'_> {
    pub(crate) fn collect_property_values(
        &mut self,
        elements: &mut Vec<DavPropertyValue>,
    ) -> crate::parser::Result<()> {
        loop {
            match self.token()? {
                Token::ElementStart { name, .. } => {
                    if let Some(property) = DavProperty::from_element(name) {
                        let value = match property {
                            DavProperty::WebDav(WebDavProperty::ResourceType) => {
                                DavValue::ResourceTypes(List(self.collect_elements()?))
                            }
                            DavProperty::WebDav(WebDavProperty::CreationDate) => {
                                match self.parse_value::<DateTime>()? {
                                    Some(Ok(value)) => DavValue::Timestamp(value.to_timestamp()),
                                    Some(Err(value)) => DavValue::String(value),
                                    None => DavValue::Null,
                                }
                            }
                            DavProperty::CalDav(CalDavProperty::CalendarTimezone) => {
                                match self.parse_value()? {
                                    Some(Ok(value)) => DavValue::ICalendar(value),
                                    Some(Err(value)) => DavValue::String(value),
                                    None => DavValue::Null,
                                }
                            }
                            DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet) => {
                                let mut components = Vec::new();

                                loop {
                                    match self.token()? {
                                        Token::ElementStart { name, raw } => {
                                            if name.ns == Namespace::CalDav
                                                && name.element == Element::Comp
                                            {
                                                for component in
                                                    raw.attributes::<ICalendarComponentType>()
                                                {
                                                    if let Attribute::Name(name) = component? {
                                                        components.push(Comp(name));
                                                    }
                                                }
                                            }
                                            self.seek_element_end()?;
                                        }
                                        Token::UnknownElement(_) => {
                                            // Ignore unknown elements
                                            self.seek_element_end()?;
                                        }
                                        Token::ElementEnd | Token::Eof => {
                                            break;
                                        }
                                        _ => {}
                                    }
                                }

                                DavValue::Components(List(components))
                            }
                            DavProperty::CalDav(
                                CalDavProperty::MaxInstances
                                | CalDavProperty::MaxAttendeesPerInstance,
                            ) => match self.parse_value()? {
                                Some(Ok(value)) => DavValue::Uint64(value),
                                Some(Err(value)) => DavValue::String(value),
                                None => DavValue::Null,
                            },
                            _ => self
                                .collect_string_value()?
                                .map(DavValue::String)
                                .unwrap_or(DavValue::Null),
                        };

                        elements.push(DavPropertyValue { property, value });
                    } else {
                        // Ignore unknown elements
                        self.seek_element_end()?;
                    }
                }
                Token::ElementEnd | Token::Eof => {
                    break;
                }
                Token::UnknownElement(raw) => {
                    elements.push(DavPropertyValue {
                        property: DavProperty::DeadProperty((&raw).into()),
                        value: DavValue::DeadProperty(DeadProperty::parse(self)?),
                    });
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(())
    }
}

impl TimeRange {
    pub fn is_in_range(&self, match_overlap: bool, start: i64, end: i64) -> bool {
        /*let c = println!(
            "is_in_range ({match_overlap}): {} to {}, resource from {} to {}, result: {}",
            chrono::DateTime::from_timestamp(self.start, 0).unwrap(),
            chrono::DateTime::from_timestamp(self.end, 0).unwrap(),
            chrono::DateTime::from_timestamp(start, 0).unwrap(),
            chrono::DateTime::from_timestamp(end, 0).unwrap(),
            result
        );*/
        if !match_overlap {
            // RFC4791#9.9: (start <  DTEND AND end > DTSTART)
            self.start < end && self.end > start
        } else {
            // RFC4791#9.9: ((start <  DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))
            ((start < self.end) || (start <= self.start)) && (end > self.start || end >= self.end)
        }
    }

    pub fn from_raw(raw: &RawElement<'_>) -> super::Result<Option<Self>> {
        let mut range = TimeRange {
            start: i64::MIN,
            end: i64::MAX,
        };

        for attribute in raw.attributes::<ICalendarDateTime>() {
            match attribute? {
                Attribute::Start(start) => {
                    range.start = start.0;
                }
                Attribute::End(end) => {
                    range.end = end.0;
                }
                _ => {}
            }
        }

        if range.end < range.start {
            range.end = i64::MAX;
        }

        if range.start != i64::MIN || range.end != i64::MAX {
            Ok(Some(range))
        } else {
            Ok(None)
        }
    }
}

impl DavProperty {
    pub(crate) fn from_element(element: NamedElement) -> Option<Self> {
        match (element.ns, element.element) {
            (Namespace::Dav, Element::Creationdate) => {
                Some(DavProperty::WebDav(WebDavProperty::CreationDate))
            }
            (Namespace::Dav, Element::Displayname) => {
                Some(DavProperty::WebDav(WebDavProperty::DisplayName))
            }
            (Namespace::Dav, Element::Getcontentlanguage) => {
                Some(DavProperty::WebDav(WebDavProperty::GetContentLanguage))
            }
            (Namespace::Dav, Element::Getcontentlength) => {
                Some(DavProperty::WebDav(WebDavProperty::GetContentLength))
            }
            (Namespace::Dav, Element::Getcontenttype) => {
                Some(DavProperty::WebDav(WebDavProperty::GetContentType))
            }
            (Namespace::Dav, Element::Getetag) => {
                Some(DavProperty::WebDav(WebDavProperty::GetETag))
            }
            (Namespace::Dav, Element::Getlastmodified) => {
                Some(DavProperty::WebDav(WebDavProperty::GetLastModified))
            }
            (Namespace::Dav, Element::Resourcetype) => {
                Some(DavProperty::WebDav(WebDavProperty::ResourceType))
            }
            (Namespace::Dav, Element::Lockdiscovery) => {
                Some(DavProperty::WebDav(WebDavProperty::LockDiscovery))
            }
            (Namespace::Dav, Element::Supportedlock) => {
                Some(DavProperty::WebDav(WebDavProperty::SupportedLock))
            }
            (Namespace::Dav, Element::CurrentUserPrincipal) => {
                Some(DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal))
            }
            (Namespace::Dav, Element::QuotaAvailableBytes) => {
                Some(DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes))
            }
            (Namespace::Dav, Element::QuotaUsedBytes) => {
                Some(DavProperty::WebDav(WebDavProperty::QuotaUsedBytes))
            }
            (Namespace::Dav, Element::SupportedReportSet) => {
                Some(DavProperty::WebDav(WebDavProperty::SupportedReportSet))
            }
            (Namespace::Dav, Element::SyncToken) => {
                Some(DavProperty::WebDav(WebDavProperty::SyncToken))
            }
            (Namespace::Dav, Element::AlternateUriSet) => {
                Some(DavProperty::Principal(PrincipalProperty::AlternateURISet))
            }
            (Namespace::Dav, Element::PrincipalUrl) => {
                Some(DavProperty::Principal(PrincipalProperty::PrincipalURL))
            }
            (Namespace::Dav, Element::GroupMemberSet) => {
                Some(DavProperty::Principal(PrincipalProperty::GroupMemberSet))
            }
            (Namespace::Dav, Element::GroupMembership) => {
                Some(DavProperty::Principal(PrincipalProperty::GroupMembership))
            }
            (Namespace::Dav, Element::Owner) => Some(DavProperty::WebDav(WebDavProperty::Owner)),
            (Namespace::Dav, Element::Group) => Some(DavProperty::WebDav(WebDavProperty::Group)),
            (Namespace::Dav, Element::SupportedPrivilegeSet) => {
                Some(DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet))
            }
            (Namespace::Dav, Element::CurrentUserPrivilegeSet) => {
                Some(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
            }
            (Namespace::Dav, Element::Acl) => Some(DavProperty::WebDav(WebDavProperty::Acl)),
            (Namespace::Dav, Element::AclRestrictions) => {
                Some(DavProperty::WebDav(WebDavProperty::AclRestrictions))
            }
            (Namespace::Dav, Element::InheritedAclSet) => {
                Some(DavProperty::WebDav(WebDavProperty::InheritedAclSet))
            }
            (Namespace::Dav, Element::PrincipalCollectionSet) => {
                Some(DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet))
            }
            (Namespace::CardDav, Element::AddressbookDescription) => Some(DavProperty::CardDav(
                CardDavProperty::AddressbookDescription,
            )),
            (Namespace::CardDav, Element::SupportedAddressData) => {
                Some(DavProperty::CardDav(CardDavProperty::SupportedAddressData))
            }
            (Namespace::CardDav, Element::SupportedCollationSet) => {
                Some(DavProperty::CardDav(CardDavProperty::SupportedCollationSet))
            }
            (Namespace::CardDav, Element::AddressbookHomeSet) => Some(DavProperty::Principal(
                PrincipalProperty::AddressbookHomeSet,
            )),
            (Namespace::CardDav, Element::PrincipalAddress) => {
                Some(DavProperty::Principal(PrincipalProperty::PrincipalAddress))
            }
            (Namespace::CardDav, Element::AddressData) => Some(DavProperty::CardDav(
                CardDavProperty::AddressData(Default::default()),
            )),
            (Namespace::CardDav, Element::MaxResourceSize) => {
                Some(DavProperty::CardDav(CardDavProperty::MaxResourceSize))
            }
            (Namespace::CalDav, Element::CalendarDescription) => {
                Some(DavProperty::CalDav(CalDavProperty::CalendarDescription))
            }
            (Namespace::CalDav, Element::CalendarTimezone) => {
                Some(DavProperty::CalDav(CalDavProperty::CalendarTimezone))
            }
            (Namespace::CalDav, Element::SupportedCalendarComponentSet) => Some(
                DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
            ),
            (Namespace::CalDav, Element::SupportedCollationSet) => {
                Some(DavProperty::CalDav(CalDavProperty::SupportedCollationSet))
            }
            (Namespace::CalDav, Element::SupportedCalendarData) => {
                Some(DavProperty::CalDav(CalDavProperty::SupportedCalendarData))
            }
            (Namespace::CalDav, Element::MaxResourceSize) => {
                Some(DavProperty::CalDav(CalDavProperty::MaxResourceSize))
            }
            (Namespace::CalDav, Element::MinDateTime) => {
                Some(DavProperty::CalDav(CalDavProperty::MinDateTime))
            }
            (Namespace::CalDav, Element::MaxDateTime) => {
                Some(DavProperty::CalDav(CalDavProperty::MaxDateTime))
            }
            (Namespace::CalDav, Element::MaxInstances) => {
                Some(DavProperty::CalDav(CalDavProperty::MaxInstances))
            }
            (Namespace::CalDav, Element::MaxAttendeesPerInstance) => {
                Some(DavProperty::CalDav(CalDavProperty::MaxAttendeesPerInstance))
            }
            (Namespace::CalDav, Element::CalendarHomeSet) => {
                Some(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
            }
            (Namespace::CalDav, Element::CalendarData) => Some(DavProperty::CalDav(
                CalDavProperty::CalendarData(Default::default()),
            )),
            (Namespace::CalDav, Element::TimezoneServiceSet) => {
                Some(DavProperty::CalDav(CalDavProperty::TimezoneServiceSet))
            }
            (Namespace::CalDav, Element::CalendarTimezoneId) => {
                Some(DavProperty::CalDav(CalDavProperty::TimezoneId))
            }
            (Namespace::CalendarServer, Element::Getctag) => {
                Some(DavProperty::WebDav(WebDavProperty::GetCTag))
            }
            _ => None,
        }
    }
}

impl TryFrom<NamedElement> for ResourceType {
    type Error = ();

    fn try_from(value: NamedElement) -> Result<Self, Self::Error> {
        match (value.ns, value.element) {
            (Namespace::Dav, Element::Collection) => Ok(ResourceType::Collection),
            (Namespace::Dav, Element::Principal) => Ok(ResourceType::Principal),
            (Namespace::CardDav, Element::Addressbook) => Ok(ResourceType::AddressBook),
            (Namespace::CalDav, Element::Calendar) => Ok(ResourceType::Calendar),
            _ => Err(()),
        }
    }
}

struct ICalendarDateTime(i64);

impl AttributeValue for ICalendarDateTime {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        let mut dt = PartialDateTime::default();
        dt.parse_timestamp(&mut s.as_bytes().iter().peekable(), true);
        dt.to_timestamp().map(ICalendarDateTime)
    }
}

impl AttributeValue for ICalendarComponentType {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ICalendarComponentType::try_from(s.as_bytes()).ok()
    }
}

impl AttributeValue for ICalendarProperty {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ICalendarProperty::try_from(s.as_bytes())
            .unwrap_or_else(|_| ICalendarProperty::Other(s.to_string()))
            .into()
    }
}

impl AttributeValue for ICalendarParameterName {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        ICalendarParameterName::parse(s).into()
    }
}

impl AttributeValue for VCardPropertyWithGroup {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        if let Some((group, s)) = s.split_once('.') {
            VCardPropertyWithGroup {
                name: VCardProperty::try_from(s.as_bytes())
                    .unwrap_or_else(|_| VCardProperty::Other(s.to_string())),
                group: group.to_string().into(),
            }
            .into()
        } else {
            VCardPropertyWithGroup {
                name: VCardProperty::try_from(s.as_bytes())
                    .unwrap_or_else(|_| VCardProperty::Other(s.to_string())),
                group: None,
            }
            .into()
        }
    }
}

impl AttributeValue for VCardParameterName {
    fn from_str(s: &str) -> Option<Self>
    where
        Self: Sized,
    {
        VCardParameterName::parse(s).into()
    }
}

impl XmlValueParser for ICalendar {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(bytes);
        let mut parser = Parser::new(&text);
        if let Entry::ICalendar(ical) = parser.entry() {
            Some(ical)
        } else {
            None
        }
    }

    fn parse_str(text: &str) -> Option<Self> {
        let mut parser = Parser::new(text);
        if let Entry::ICalendar(ical) = parser.entry() {
            Some(ical)
        } else {
            None
        }
    }
}

impl XmlValueParser for u64 {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        std::str::from_utf8(bytes).ok().and_then(|s| s.parse().ok())
    }

    fn parse_str(text: &str) -> Option<Self> {
        text.parse().ok()
    }
}

impl XmlValueParser for u32 {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        std::str::from_utf8(bytes).ok().and_then(|s| s.parse().ok())
    }

    fn parse_str(text: &str) -> Option<Self> {
        text.parse().ok()
    }
}

impl XmlValueParser for DateTime {
    fn parse_bytes(bytes: &[u8]) -> Option<Self> {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(DateTime::parse_rfc3339)
    }

    fn parse_str(text: &str) -> Option<Self> {
        DateTime::parse_rfc3339(text)
    }
}
