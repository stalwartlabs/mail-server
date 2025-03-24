/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use calcard::{icalendar::ICalendar, vcard::VCard};
use mail_parser::{
    parsers::fields::date::{DOW, MONTH},
    DateTime,
};

use crate::schema::{
    property::{
        ActiveLock, CalDavProperty, CardDavProperty, Comp, DavProperty, DavValue, LockDiscovery,
        LockEntry, Privilege, ReportSet, ResourceType, Rfc1123DateTime, SupportedCollation,
        SupportedLock, WebDavProperty,
    },
    request::{DavPropertyValue, DeadProperty},
    response::{Ace, AclRestrictions, Href, List, PropResponse, SupportedPrivilege},
    Namespace,
};

use super::XmlEscape;

impl Display for PropResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:prop {}>{}</D:prop>", self.namespace, self.properties)
    }
}

impl Display for DavPropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, attrs) = self.property.tag_name();
        if let Some(attrs) = attrs {
            write!(f, "<{} {}>{}</{}>", name, attrs, self.value, name)
        } else {
            write!(f, "<{}>{}</{}>", name, self.value, name)
        }
    }
}

impl Display for Rfc1123DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dt = DateTime::from_timestamp(self.0);
        write!(
            f,
            "{}, {} {} {:04} {:02}:{:02}:{:02} GMT",
            DOW[dt.day_of_week() as usize],
            dt.day,
            MONTH
                .get(dt.month.saturating_sub(1) as usize)
                .copied()
                .unwrap_or_default(),
            dt.year,
            dt.hour,
            dt.minute,
            dt.second,
        )
    }
}

impl Display for DavValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DavValue::Timestamp(v) => {
                let dt = DateTime::from_timestamp(*v);
                write!(
                    f,
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
                )
            }
            DavValue::Rfc1123Date(v) => v.fmt(f),
            DavValue::Uint64(v) => v.fmt(f),
            DavValue::String(v) => v.write_escaped_to(f),
            DavValue::ResourceTypes(v) => v.fmt(f),
            DavValue::ActiveLocks(v) => v.fmt(f),
            DavValue::LockEntries(v) => v.fmt(f),
            DavValue::ReportSets(v) => v.fmt(f),
            DavValue::VCard(v) => {
                write!(f, "<![CDATA[{v}]]>")
            }
            DavValue::ICalendar(v) => {
                write!(f, "<![CDATA[{v}]]>")
            }
            DavValue::Components(v) => v.fmt(f),
            DavValue::Collations(v) => v.fmt(f),
            DavValue::Href(v) => v.fmt(f),
            DavValue::PrivilegeSet(v) => v.fmt(f),
            DavValue::Privileges(v) => v.fmt(f),
            DavValue::Acl(v) => v.fmt(f),
            DavValue::AclRestrictions(v) => v.fmt(f),
            DavValue::DeadProperty(v) => v.fmt(f),
            DavValue::Null => Ok(()),
        }
    }
}

impl DavProperty {
    fn tag_name(&self) -> (&str, Option<&str>) {
        (
            match self {
                DavProperty::WebDav(prop) => match prop {
                    WebDavProperty::CreationDate => "D:creationdate",
                    WebDavProperty::DisplayName => "D:displayname",
                    WebDavProperty::GetContentLanguage => "D:getcontentlanguage",
                    WebDavProperty::GetContentLength => "D:getcontentlength",
                    WebDavProperty::GetContentType => "D:getcontenttype",
                    WebDavProperty::GetETag => "D:getetag",
                    WebDavProperty::GetLastModified => "D:getlastmodified",
                    WebDavProperty::ResourceType => "D:resourcetype",
                    WebDavProperty::LockDiscovery => "D:lockdiscovery",
                    WebDavProperty::SupportedLock => "D:supportedlock",
                    WebDavProperty::CurrentUserPrincipal => "D:current-user-principal",
                    WebDavProperty::QuotaAvailableBytes => "D:quota-available-bytes",
                    WebDavProperty::QuotaUsedBytes => "D:quota-used-bytes",
                    WebDavProperty::SupportedReportSet => "D:supported-report-set",
                    WebDavProperty::SyncToken => "D:sync-token",
                    WebDavProperty::AlternateURISet => "D:alternate-URI-set",
                    WebDavProperty::PrincipalURL => "D:principal-URL",
                    WebDavProperty::GroupMemberSet => "D:group-member-set",
                    WebDavProperty::GroupMembership => "D:group-membership",
                    WebDavProperty::Owner => "D:owner",
                    WebDavProperty::Group => "D:group",
                    WebDavProperty::SupportedPrivilegeSet => "D:supported-privilege-set",
                    WebDavProperty::CurrentUserPrivilegeSet => "D:current-user-privilege-set",
                    WebDavProperty::Acl => "D:acl",
                    WebDavProperty::AclRestrictions => "D:acl-restrictions",
                    WebDavProperty::InheritedAclSet => "D:inherited-acl-set",
                    WebDavProperty::PrincipalCollectionSet => "D:principal-collection-set",
                },
                DavProperty::CardDav(prop) => match prop {
                    CardDavProperty::AddressbookDescription => "C:addressbook-description",
                    CardDavProperty::SupportedAddressData => "C:supported-address-data",
                    CardDavProperty::SupportedCollationSet => "C:supported-collation-set",
                    CardDavProperty::MaxResourceSize => "C:max-resource-size",
                    CardDavProperty::AddressData(_) => "C:address-data",
                },
                DavProperty::CalDav(prop) => match prop {
                    CalDavProperty::CalendarDescription => "C:calendar-description",
                    CalDavProperty::CalendarTimezone => "C:calendar-timezone",
                    CalDavProperty::SupportedCalendarComponentSet => {
                        "C:supported-calendar-component-set"
                    }
                    CalDavProperty::SupportedCalendarData => "C:supported-calendar-data",
                    CalDavProperty::SupportedCollationSet => "C:supported-collation-set",
                    CalDavProperty::MaxResourceSize => "C:max-resource-size",
                    CalDavProperty::MinDateTime => "C:min-date-time",
                    CalDavProperty::MaxDateTime => "C:max-date-time",
                    CalDavProperty::MaxInstances => "C:max-instances",
                    CalDavProperty::MaxAttendeesPerInstance => "C:max-attendees-per-instance",
                    CalDavProperty::CalendarHomeSet => "C:calendar-home-set",
                    CalDavProperty::CalendarData(_) => "C:calendar-data",
                    CalDavProperty::TimezoneServiceSet => "C:timezone-service-set",
                    CalDavProperty::TimezoneId => "C:calendar-timezone-id",
                },
                DavProperty::DeadProperty(dead) => {
                    return (dead.name.as_str(), dead.attrs.as_deref())
                }
            },
            None,
        )
    }
}

impl Display for ReportSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportSet::SyncCollection => write!(f, "<D:sync-collection/>"),
        }
    }
}

impl Display for DavProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, attrs) = self.tag_name();
        if let Some(attrs) = attrs {
            write!(f, "<{name} {attrs}/>")
        } else {
            write!(f, "<{name}/>")
        }
    }
}

impl PropResponse {
    pub fn new(properties: Vec<DavPropertyValue>) -> Self {
        PropResponse {
            namespace: Namespace::Dav,
            properties: List(properties),
        }
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespace = namespace;
        self
    }
}

impl From<WebDavProperty> for DavProperty {
    fn from(prop: WebDavProperty) -> Self {
        DavProperty::WebDav(prop)
    }
}

impl From<CardDavProperty> for DavProperty {
    fn from(prop: CardDavProperty) -> Self {
        DavProperty::CardDav(prop)
    }
}

impl From<CalDavProperty> for DavProperty {
    fn from(prop: CalDavProperty) -> Self {
        DavProperty::CalDav(prop)
    }
}

impl From<String> for DavValue {
    fn from(v: String) -> Self {
        DavValue::String(v)
    }
}

impl From<&str> for DavValue {
    fn from(v: &str) -> Self {
        DavValue::String(v.to_string())
    }
}

impl From<u64> for DavValue {
    fn from(v: u64) -> Self {
        DavValue::Uint64(v)
    }
}

impl From<DateTime> for DavValue {
    fn from(v: DateTime) -> Self {
        DavValue::Timestamp(v.to_timestamp())
    }
}

impl From<Vec<ResourceType>> for DavValue {
    fn from(v: Vec<ResourceType>) -> Self {
        DavValue::ResourceTypes(List(v))
    }
}

impl From<Vec<ReportSet>> for DavValue {
    fn from(v: Vec<ReportSet>) -> Self {
        DavValue::ReportSets(List(v))
    }
}

impl From<Vec<Comp>> for DavValue {
    fn from(v: Vec<Comp>) -> Self {
        DavValue::Components(List(v))
    }
}

impl From<Vec<SupportedCollation>> for DavValue {
    fn from(v: Vec<SupportedCollation>) -> Self {
        DavValue::Collations(List(v))
    }
}

impl From<ICalendar> for DavValue {
    fn from(v: ICalendar) -> Self {
        DavValue::ICalendar(v)
    }
}

impl From<VCard> for DavValue {
    fn from(v: VCard) -> Self {
        DavValue::VCard(v)
    }
}

impl From<SupportedLock> for DavValue {
    fn from(v: SupportedLock) -> Self {
        DavValue::LockEntries(v.0)
    }
}

impl From<Vec<LockEntry>> for DavValue {
    fn from(v: Vec<LockEntry>) -> Self {
        DavValue::LockEntries(List(v))
    }
}

impl From<Vec<ActiveLock>> for DavValue {
    fn from(v: Vec<ActiveLock>) -> Self {
        DavValue::ActiveLocks(List(v))
    }
}

impl From<LockDiscovery> for DavValue {
    fn from(v: LockDiscovery) -> Self {
        DavValue::ActiveLocks(v.0)
    }
}

impl From<Vec<SupportedPrivilege>> for DavValue {
    fn from(v: Vec<SupportedPrivilege>) -> Self {
        DavValue::PrivilegeSet(List(v))
    }
}

impl From<Vec<Privilege>> for DavValue {
    fn from(v: Vec<Privilege>) -> Self {
        DavValue::Privileges(List(v))
    }
}

impl From<Vec<Href>> for DavValue {
    fn from(v: Vec<Href>) -> Self {
        DavValue::Href(List(v))
    }
}

impl From<Vec<Ace>> for DavValue {
    fn from(v: Vec<Ace>) -> Self {
        DavValue::Acl(List(v))
    }
}

impl From<AclRestrictions> for DavValue {
    fn from(v: AclRestrictions) -> Self {
        DavValue::AclRestrictions(v)
    }
}

impl From<DeadProperty> for DavValue {
    fn from(v: DeadProperty) -> Self {
        DavValue::DeadProperty(v)
    }
}

impl DavPropertyValue {
    pub fn new(property: impl Into<DavProperty>, value: impl Into<DavValue>) -> Self {
        DavPropertyValue {
            property: property.into(),
            value: value.into(),
        }
    }

    pub fn empty(property: impl Into<DavProperty>) -> Self {
        DavPropertyValue {
            property: property.into(),
            value: DavValue::Null,
        }
    }
}
