/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{XmlCdataEscape, XmlEscape};
use crate::schema::{
    property::{
        ActiveLock, CalDavProperty, CardDavProperty, Comp, DavProperty, DavValue, LockDiscovery,
        LockEntry, PrincipalProperty, Privilege, ReportSet, ResourceType, Rfc1123DateTime,
        SupportedCollation, SupportedLock, WebDavProperty,
    },
    request::{DavPropertyValue, DeadProperty},
    response::{Ace, AclRestrictions, Href, List, PropResponse, SupportedPrivilege},
    Namespace, Namespaces,
};
use mail_parser::{
    parsers::fields::date::{DOW, MONTH},
    DateTime,
};
use std::fmt::Display;

impl Display for PropResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><D:prop {}>{}</D:prop>",
            self.namespaces, self.properties
        )
    }
}

impl Display for DavPropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, attrs) = self.property.tag_name();

        write!(f, "<{}", name)?;

        if let Some(attrs) = attrs {
            write!(f, " {attrs}")?;
        }

        if !matches!(self.value, DavValue::Null) {
            write!(f, ">{}</{}>", self.value, name)
        } else {
            write!(f, "/>")
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
            DavValue::CData(v) => v.write_cdata_escaped_to(f),
            DavValue::Components(v) => v.fmt(f),
            DavValue::Collations(v) => v.fmt(f),
            DavValue::Href(v) => v.fmt(f),
            DavValue::PrivilegeSet(v) => v.fmt(f),
            DavValue::Privileges(v) => v.fmt(f),
            DavValue::Acl(v) => v.fmt(f),
            DavValue::AclRestrictions(v) => v.fmt(f),
            DavValue::DeadProperty(v) => v.fmt(f),
            DavValue::SupportedAddressData => {
                write!(
                    f,
                    concat!(
                        "<B:address-data-type content-type=\"text/vcard\" version=\"4.0\"/>",
                        "<B:address-data-type content-type=\"text/vcard\" version=\"3.0\"/>",
                        "<B:address-data-type content-type=\"text/vcard\" version=\"2.1\"/>",
                    )
                )
            }
            DavValue::SupportedCalendarData => {
                write!(
                    f,
                    concat!(
                        "<A:calendar-data-type content-type=\"text/calendar\" version=\"2.0\"/>",
                        "<A:calendar-data-type content-type=\"text/calendar\" version=\"1.0\"/>",
                    )
                )
            }
            DavValue::SupportedCalendarComponentSet => {
                write!(
                    f,
                    concat!(
                        "<A:comp name=\"VEVENT\"/>",
                        "<A:comp name=\"VTODO\"/>",
                        "<A:comp name=\"VJOURNAL\"/>",
                        "<A:comp name=\"VFREEBUSY\"/>",
                        "<A:comp name=\"VTIMEZONE\"/>",
                        "<A:comp name=\"VALARM\"/>",
                        "<A:comp name=\"STANDARD\"/>",
                        "<A:comp name=\"DAYLIGHT\"/>",
                        "<A:comp name=\"VAVAILABILITY\"/>",
                        "<A:comp name=\"AVAILABLE\"/>",
                        "<A:comp name=\"PARTICIPANT\"/>",
                        "<A:comp name=\"VLOCATION\"/>",
                        "<A:comp name=\"VRESOURCE\"/>",
                    )
                )
            }
            DavValue::Response(v) => v.fmt(f),
            DavValue::VCard(_) | DavValue::ICalendar(_) | DavValue::Null => Ok(()),
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
                    WebDavProperty::Owner => "D:owner",
                    WebDavProperty::Group => "D:group",
                    WebDavProperty::SupportedPrivilegeSet => "D:supported-privilege-set",
                    WebDavProperty::CurrentUserPrivilegeSet => "D:current-user-privilege-set",
                    WebDavProperty::Acl => "D:acl",
                    WebDavProperty::AclRestrictions => "D:acl-restrictions",
                    WebDavProperty::InheritedAclSet => "D:inherited-acl-set",
                    WebDavProperty::PrincipalCollectionSet => "D:principal-collection-set",
                    WebDavProperty::GetCTag => "C:getctag",
                },
                DavProperty::CardDav(prop) => match prop {
                    CardDavProperty::AddressbookDescription => "B:addressbook-description",
                    CardDavProperty::SupportedAddressData => "B:supported-address-data",
                    CardDavProperty::SupportedCollationSet => "B:supported-collation-set",
                    CardDavProperty::MaxResourceSize => "B:max-resource-size",
                    CardDavProperty::AddressData(_) => "B:address-data",
                },
                DavProperty::CalDav(prop) => match prop {
                    CalDavProperty::CalendarDescription => "A:calendar-description",
                    CalDavProperty::CalendarTimezone => "A:calendar-timezone",
                    CalDavProperty::SupportedCalendarComponentSet => {
                        "A:supported-calendar-component-set"
                    }
                    CalDavProperty::SupportedCalendarData => "A:supported-calendar-data",
                    CalDavProperty::SupportedCollationSet => "A:supported-collation-set",
                    CalDavProperty::MaxResourceSize => "A:max-resource-size",
                    CalDavProperty::MinDateTime => "A:min-date-time",
                    CalDavProperty::MaxDateTime => "A:max-date-time",
                    CalDavProperty::MaxInstances => "A:max-instances",
                    CalDavProperty::MaxAttendeesPerInstance => "A:max-attendees-per-instance",
                    CalDavProperty::CalendarData(_) => "A:calendar-data",
                    CalDavProperty::TimezoneServiceSet => "A:timezone-service-set",
                    CalDavProperty::TimezoneId => "A:calendar-timezone-id",
                },
                DavProperty::Principal(prop) => match prop {
                    PrincipalProperty::AlternateURISet => "D:alternate-URI-set",
                    PrincipalProperty::PrincipalURL => "D:principal-URL",
                    PrincipalProperty::GroupMemberSet => "D:group-member-set",
                    PrincipalProperty::GroupMembership => "D:group-membership",
                    PrincipalProperty::CalendarHomeSet => "A:calendar-home-set",
                    PrincipalProperty::AddressbookHomeSet => "B:addressbook-home-set",
                    PrincipalProperty::PrincipalAddress => "B:principal-address",
                },
                DavProperty::DeadProperty(dead) => {
                    return (dead.name.as_str(), dead.attrs.as_deref())
                }
            },
            None,
        )
    }

    pub fn namespace(&self) -> Namespace {
        match self {
            DavProperty::WebDav(WebDavProperty::GetCTag) => Namespace::CalendarServer,
            DavProperty::CardDav(_)
            | DavProperty::Principal(PrincipalProperty::AddressbookHomeSet) => Namespace::CardDav,
            DavProperty::CalDav(_) | DavProperty::Principal(PrincipalProperty::CalendarHomeSet) => {
                Namespace::CalDav
            }
            _ => Namespace::Dav,
        }
    }
}

impl AsRef<str> for DavProperty {
    fn as_ref(&self) -> &str {
        self.tag_name().0
    }
}

impl Display for ReportSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<D:supported-report><D:report>")?;
        match self {
            ReportSet::SyncCollection => write!(f, "<D:sync-collection/>"),
            ReportSet::ExpandProperty => write!(f, "<D:expand-property/>"),
            ReportSet::AddressbookQuery => write!(f, "<B:addressbook-query/>"),
            ReportSet::AddressbookMultiGet => write!(f, "<B:addressbook-multiget/>"),
            ReportSet::CalendarQuery => write!(f, "<A:calendar-query/>"),
            ReportSet::CalendarMultiGet => write!(f, "<A:calendar-multiget/>"),
            ReportSet::FreeBusyQuery => write!(f, "<A:free-busy-query/>"),
            ReportSet::AclPrincipalPropSet => write!(f, "<D:acl-principal-prop-set/>"),
            ReportSet::PrincipalMatch => write!(f, "<D:principal-match/>"),
            ReportSet::PrincipalPropertySearch => write!(f, "<D:principal-property-search/>"),
            ReportSet::PrincipalSearchPropertySet => {
                write!(f, "<D:principal-search-property-set/>")
            }
        }?;
        f.write_str("</D:report></D:supported-report>")
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
            namespaces: Namespaces::default(),
            properties: List(properties),
        }
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespaces.set(namespace);
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
