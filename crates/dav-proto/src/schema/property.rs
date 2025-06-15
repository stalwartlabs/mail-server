/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    icalendar::{ICalendar, ICalendarComponentType, ICalendarProperty},
    vcard::{VCard, VCardProperty},
};

use crate::{Depth, Timeout};

use super::{
    request::{DavPropertyValue, DeadElementTag, DeadProperty},
    response::{Ace, AclRestrictions, Href, List, Response, SupportedPrivilege},
    Collation, Namespace,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum DavProperty {
    WebDav(WebDavProperty),
    CardDav(CardDavProperty),
    CalDav(CalDavProperty),
    Principal(PrincipalProperty),
    DeadProperty(DeadElementTag),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum WebDavProperty {
    CreationDate,
    DisplayName,
    GetContentLanguage,
    GetContentLength,
    GetContentType,
    GetETag,
    GetLastModified,
    ResourceType,
    LockDiscovery,
    SupportedLock,
    SupportedReportSet,
    CurrentUserPrincipal,
    // Quota properties
    QuotaAvailableBytes,
    QuotaUsedBytes,
    // Sync properties
    SyncToken,
    // ACL properties (all protected)
    Owner,
    Group,
    SupportedPrivilegeSet,
    CurrentUserPrivilegeSet,
    Acl,
    AclRestrictions,
    InheritedAclSet,
    PrincipalCollectionSet,
    // Apple proprietary properties
    GetCTag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum CardDavProperty {
    AddressbookDescription,
    SupportedAddressData,
    SupportedCollationSet,
    MaxResourceSize,
    AddressData(Vec<CardDavPropertyName>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct CardDavPropertyName {
    pub group: Option<String>,
    pub name: VCardProperty,
    pub no_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum CalDavProperty {
    CalendarDescription,
    CalendarTimezone,
    SupportedCalendarComponentSet,
    SupportedCalendarData,
    SupportedCollationSet,
    MaxResourceSize,
    MinDateTime,
    MaxDateTime,
    MaxInstances,
    MaxAttendeesPerInstance,
    CalendarData(CalendarData),
    TimezoneServiceSet,
    TimezoneId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum PrincipalProperty {
    AlternateURISet,
    PrincipalURL,
    GroupMemberSet,
    GroupMembership,
    CalendarHomeSet,
    AddressbookHomeSet,
    PrincipalAddress,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct CalendarData {
    pub properties: Vec<CalDavPropertyName>,
    pub expand: Option<TimeRange>,
    pub limit_recurrence: Option<TimeRange>,
    pub limit_freebusy: Option<TimeRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct CalDavPropertyName {
    pub component: Option<ICalendarComponentType>,
    pub name: Option<ICalendarProperty>,
    pub no_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Rfc1123DateTime(pub(crate) i64);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum DavValue {
    Timestamp(i64),
    Rfc1123Date(Rfc1123DateTime),
    Uint64(u64),
    String(String),
    CData(String),
    ResourceTypes(List<ResourceType>),
    ActiveLocks(List<ActiveLock>),
    LockEntries(List<LockEntry>),
    ReportSets(List<ReportSet>),
    ICalendar(ICalendar),
    VCard(VCard),
    Components(List<Comp>),
    Collations(List<SupportedCollation>),
    PrivilegeSet(List<SupportedPrivilege>),
    Privileges(List<Privilege>),
    Href(List<Href>),
    Acl(List<Ace>),
    AclRestrictions(AclRestrictions),
    Response(Response),
    DeadProperty(DeadProperty),
    SupportedAddressData,
    SupportedCalendarData,
    SupportedCalendarComponentSet,
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum ReportSet {
    SyncCollection,
    ExpandProperty,
    AddressbookQuery,
    AddressbookMultiGet,
    CalendarQuery,
    CalendarMultiGet,
    FreeBusyQuery,
    AclPrincipalPropSet,
    PrincipalMatch,
    PrincipalPropertySearch,
    PrincipalSearchPropertySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct Comp(pub ICalendarComponentType);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct SupportedCollation {
    pub collation: Collation,
    pub namespace: Namespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum ResourceType {
    Collection,
    Principal,
    AddressBook,
    Calendar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct LockDiscovery(pub List<ActiveLock>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct ActiveLock {
    pub lock_scope: LockScope,
    pub lock_type: LockType,
    pub depth: Depth,
    pub owner: Option<DeadProperty>,
    pub timeout: Timeout,
    pub lock_token: Option<Href>,
    pub lock_root: Href,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct SupportedLock(pub List<LockEntry>);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct LockEntry {
    pub lock_scope: LockScope,
    pub lock_type: LockType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum LockType {
    Write,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum LockScope {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Privilege {
    Read,
    Write,
    WriteProperties,
    WriteContent,
    Unlock,
    ReadAcl,
    ReadCurrentUserPrivilegeSet,
    WriteAcl,
    Bind,
    Unbind,
    All,
    ReadFreeBusy,
}

impl Privilege {
    pub fn all(is_calendar: bool) -> Vec<Privilege> {
        if is_calendar {
            vec![
                Privilege::All,
                Privilege::Read,
                Privilege::Write,
                Privilege::WriteProperties,
                Privilege::WriteContent,
                Privilege::Unlock,
                Privilege::ReadAcl,
                Privilege::ReadCurrentUserPrivilegeSet,
                Privilege::WriteAcl,
                Privilege::Bind,
                Privilege::Unbind,
                Privilege::ReadFreeBusy,
            ]
        } else {
            vec![
                Privilege::All,
                Privilege::Read,
                Privilege::Write,
                Privilege::WriteProperties,
                Privilege::WriteContent,
                Privilege::Unlock,
                Privilege::ReadAcl,
                Privilege::ReadCurrentUserPrivilegeSet,
                Privilege::WriteAcl,
                Privilege::Bind,
                Privilege::Unbind,
            ]
        }
    }
}

impl From<DavProperty> for DavPropertyValue {
    fn from(value: DavProperty) -> Self {
        DavPropertyValue {
            property: value,
            value: DavValue::Null,
        }
    }
}

impl Rfc1123DateTime {
    pub fn new(timestamp: i64) -> Self {
        Self(timestamp)
    }
}

impl DavProperty {
    pub const ALL_PROPS: [DavProperty; 11] = [
        DavProperty::WebDav(WebDavProperty::CreationDate),
        DavProperty::WebDav(WebDavProperty::DisplayName),
        DavProperty::WebDav(WebDavProperty::GetETag),
        DavProperty::WebDav(WebDavProperty::GetLastModified),
        DavProperty::WebDav(WebDavProperty::ResourceType),
        DavProperty::WebDav(WebDavProperty::LockDiscovery),
        DavProperty::WebDav(WebDavProperty::SupportedLock),
        DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
        DavProperty::WebDav(WebDavProperty::GetContentLanguage),
        DavProperty::WebDav(WebDavProperty::GetContentLength),
        DavProperty::WebDav(WebDavProperty::GetContentType),
    ];

    pub fn is_all_prop(&self) -> bool {
        matches!(
            self,
            DavProperty::WebDav(WebDavProperty::CreationDate)
                | DavProperty::WebDav(WebDavProperty::DisplayName)
                | DavProperty::WebDav(WebDavProperty::GetETag)
                | DavProperty::WebDav(WebDavProperty::GetLastModified)
                | DavProperty::WebDav(WebDavProperty::ResourceType)
                | DavProperty::WebDav(WebDavProperty::LockDiscovery)
                | DavProperty::WebDav(WebDavProperty::SupportedLock)
                | DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal)
                | DavProperty::WebDav(WebDavProperty::GetContentLanguage)
                | DavProperty::WebDav(WebDavProperty::GetContentLength)
                | DavProperty::WebDav(WebDavProperty::GetContentType)
                | DavProperty::DeadProperty(_)
        )
    }
}

impl ReportSet {
    pub fn calendar() -> Vec<ReportSet> {
        vec![
            ReportSet::SyncCollection,
            ReportSet::AclPrincipalPropSet,
            ReportSet::PrincipalMatch,
            ReportSet::ExpandProperty,
            ReportSet::CalendarQuery,
            ReportSet::CalendarMultiGet,
            ReportSet::FreeBusyQuery,
        ]
    }

    pub fn addressbook() -> Vec<ReportSet> {
        vec![
            ReportSet::SyncCollection,
            ReportSet::AclPrincipalPropSet,
            ReportSet::PrincipalMatch,
            ReportSet::ExpandProperty,
            ReportSet::AddressbookQuery,
            ReportSet::AddressbookMultiGet,
        ]
    }

    pub fn file() -> Vec<ReportSet> {
        vec![
            ReportSet::SyncCollection,
            ReportSet::AclPrincipalPropSet,
            ReportSet::PrincipalMatch,
        ]
    }

    pub fn principal() -> Vec<ReportSet> {
        vec![
            ReportSet::PrincipalPropertySearch,
            ReportSet::PrincipalSearchPropertySet,
            ReportSet::PrincipalMatch,
        ]
    }
}
