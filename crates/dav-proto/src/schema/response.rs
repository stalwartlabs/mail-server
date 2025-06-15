/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::{VCardParameterName, VCardProperty},
};
use hyper::StatusCode;

use super::{
    property::{DavProperty, Privilege},
    request::{DavPropertyValue, Filter},
    Namespaces,
};

pub struct MultiStatus {
    pub namespaces: Namespaces,
    pub response: List<Response>,
    pub response_description: Option<ResponseDescription>,
    pub sync_token: Option<SyncToken>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct Response {
    pub href: Href,
    pub typ: ResponseType,
    pub error: Option<Condition>,
    pub response_description: Option<ResponseDescription>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum ResponseType {
    PropStat(List<PropStat>),
    Status { href: List<Href>, status: Status },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Status(pub StatusCode);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Location(pub Href);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct ResponseDescription(pub String);

#[repr(transparent)]
pub struct SyncToken(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Href(pub String);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct List<T: Display>(pub Vec<T>);

pub struct MkColResponse {
    pub namespaces: Namespaces,
    pub propstat: List<PropStat>,
    pub mkcalendar: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PropStat {
    pub prop: Prop,
    pub status: Status,
    pub error: Option<Condition>,
    pub response_description: Option<ResponseDescription>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Prop(pub List<DavPropertyValue>);

pub struct PropResponse {
    pub namespaces: Namespaces,
    pub properties: List<DavPropertyValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct SupportedPrivilege {
    pub privilege: Privilege,
    pub abstract_: bool,
    pub description: String,
    pub supported_privilege: List<SupportedPrivilege>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct Ace {
    pub principal: Principal,
    pub invert: bool,
    pub grant_deny: GrantDeny,
    pub protected: bool,
    pub inherited: Option<Href>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum GrantDeny {
    Grant(List<Privilege>),
    Deny(List<Privilege>),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Principal {
    Href(Href),
    Response(Response),
    All,
    #[default]
    Authenticated,
    Unauthenticated,
    Property(List<DavPropertyValue>),
    Self_,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct AclRestrictions {
    pub grant_only: bool,
    pub no_invert: bool,
    pub deny_before_grant: bool,
    pub required_principal: Option<RequiredPrincipal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum RequiredPrincipal {
    All,
    Authenticated,
    Unauthenticated,
    Self_,
    Href(List<Href>),
    Property(Vec<DavPropertyValue>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalSearchPropertySet {
    pub namespaces: Namespaces,
    pub properties: List<PrincipalSearchProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalSearchProperty {
    pub name: DavProperty,
    pub description: String,
}

pub struct ErrorResponse {
    pub namespaces: Namespaces,
    pub error: Condition,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Condition {
    Base(BaseCondition),
    Cal(CalCondition),
    Card(CardCondition),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum BaseCondition {
    NoConflictingLock(List<Href>),
    LockTokenSubmitted(List<Href>),
    LockTokenMatchesRequestUri,
    CannotModifyProtectedProperty,
    NoExternalEntities,
    PreservedLiveProperties,
    PropFindFiniteDepth,
    ResourceMustBeNull,
    NeedPrivileges(List<Resource>),
    NoAceConflict,
    NoProtectedAceConflict,
    NoInheritedAceConflict,
    LimitedNumberOfAces,
    DenyBeforeGrant,
    GrantOnly,
    NoInvert,
    NoAbstract,
    NotSupportedPrivilege,
    MissingRequiredPrincipal,
    RecognizedPrincipal,
    AllowedPrincipal,
    NumberOfMatchesWithinLimit,
    QuotaNotExceeded,
    ValidResourceType,
    ValidSyncToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct Resource {
    pub href: Href,
    pub privilege: Privilege,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum CalCondition {
    CalendarCollectionLocationOk,
    ValidCalendarData,
    ValidFilter,
    ValidCalendarObjectResource,
    ValidTimezone,
    NoUidConflict(Href),
    InitializeCalendarCollection,
    SupportedCalendarData,
    SupportedFilter(
        Vec<Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>>,
    ),
    SupportedCollation(String),
    MinDateTime,
    MaxDateTime,
    MaxResourceSize(u32),
    MaxInstances,
    MaxAttendeesPerInstance,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum CardCondition {
    SupportedAddressData,
    SupportedAddressDataConversion,
    SupportedFilter(Vec<Filter<(), VCardProperty, VCardParameterName>>),
    SupportedCollation(String),
    ValidAddressData,
    NoUidConflict(Href),
    MaxResourceSize(u32),
    AddressBookCollectionLocationOk,
}

impl BaseCondition {
    pub fn status(&self) -> StatusCode {
        match self {
            BaseCondition::NoConflictingLock(_) => StatusCode::LOCKED,
            BaseCondition::CannotModifyProtectedProperty => StatusCode::FORBIDDEN,
            BaseCondition::LockTokenSubmitted(_) => StatusCode::LOCKED,
            BaseCondition::LockTokenMatchesRequestUri => StatusCode::CONFLICT,
            BaseCondition::NoExternalEntities => StatusCode::FORBIDDEN,
            BaseCondition::PreservedLiveProperties => StatusCode::CONFLICT,
            BaseCondition::PropFindFiniteDepth => StatusCode::FORBIDDEN,
            BaseCondition::ResourceMustBeNull => StatusCode::CONFLICT,
            BaseCondition::NeedPrivileges(_) => StatusCode::FORBIDDEN,
            BaseCondition::NumberOfMatchesWithinLimit => StatusCode::FORBIDDEN,
            _ => StatusCode::FORBIDDEN,
        }
    }
}

impl From<String> for Href {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Href {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl MultiStatus {
    pub fn is_empty(&self) -> bool {
        self.response.0.is_empty()
    }
}

impl BaseCondition {
    pub fn display_name(&self) -> &'static str {
        match self {
            BaseCondition::NoConflictingLock(_) => "NoConflictingLock",
            BaseCondition::CannotModifyProtectedProperty => "CannotModifyProtectedProperty",
            BaseCondition::LockTokenSubmitted(_) => "LockTokenSubmitted",
            BaseCondition::LockTokenMatchesRequestUri => "LockTokenMatchesRequestUri",
            BaseCondition::NoExternalEntities => "NoExternalEntities",
            BaseCondition::PreservedLiveProperties => "PreservedLiveProperties",
            BaseCondition::PropFindFiniteDepth => "PropFindFiniteDepth",
            BaseCondition::ResourceMustBeNull => "ResourceMustBeNull",
            BaseCondition::NeedPrivileges(_) => "NeedPrivileges",
            BaseCondition::NoAceConflict => "NoAceConflict",
            BaseCondition::NoProtectedAceConflict => "NoProtectedAceConflict",
            BaseCondition::NoInheritedAceConflict => "NoInheritedAceConflict",
            BaseCondition::LimitedNumberOfAces => "LimitedNumberOfAces",
            BaseCondition::DenyBeforeGrant => "DenyBeforeGrant",
            BaseCondition::GrantOnly => "GrantOnly",
            BaseCondition::NoInvert => "NoInvert",
            BaseCondition::NoAbstract => "NoAbstract",
            BaseCondition::NotSupportedPrivilege => "NotSupportedPrivilege",
            BaseCondition::MissingRequiredPrincipal => "MissingRequiredPrincipal",
            BaseCondition::RecognizedPrincipal => "RecognizedPrincipal",
            BaseCondition::AllowedPrincipal => "AllowedPrincipal",
            BaseCondition::NumberOfMatchesWithinLimit => "NumberOfMatchesWithinLimit",
            BaseCondition::QuotaNotExceeded => "QuotaNotExceeded",
            BaseCondition::ValidResourceType => "ValidResourceType",
            BaseCondition::ValidSyncToken => "ValidSyncToken",
        }
    }
}

impl CalCondition {
    pub fn display_name(&self) -> &'static str {
        match self {
            CalCondition::CalendarCollectionLocationOk => "CalendarCollectionLocationOk",
            CalCondition::ValidCalendarData => "ValidCalendarData",
            CalCondition::ValidFilter => "ValidFilter",
            CalCondition::ValidCalendarObjectResource => "ValidCalendarObjectResource",
            CalCondition::ValidTimezone => "ValidTimezone",
            CalCondition::NoUidConflict(_) => "NoUidConflict",
            CalCondition::InitializeCalendarCollection => "InitializeCalendarCollection",
            CalCondition::SupportedCalendarData => "SupportedCalendarData",
            CalCondition::SupportedFilter(_) => "SupportedFilter",
            CalCondition::SupportedCollation(_) => "SupportedCollation",
            CalCondition::MinDateTime => "MinDateTime",
            CalCondition::MaxDateTime => "MaxDateTime",
            CalCondition::MaxResourceSize(_) => "MaxResourceSize",
            CalCondition::MaxInstances => "MaxInstances",
            CalCondition::MaxAttendeesPerInstance => "MaxAttendeesPerInstance",
        }
    }
}

impl CardCondition {
    pub fn display_name(&self) -> &'static str {
        match self {
            CardCondition::SupportedAddressData => "SupportedAddressData",
            CardCondition::SupportedAddressDataConversion => "SupportedAddressDataConversion",
            CardCondition::SupportedFilter(_) => "SupportedFilter",
            CardCondition::SupportedCollation(_) => "SupportedCollation",
            CardCondition::ValidAddressData => "ValidAddressData",
            CardCondition::NoUidConflict(_) => "NoUidConflict",
            CardCondition::MaxResourceSize(_) => "MaxResourceSize",
            CardCondition::AddressBookCollectionLocationOk => "AddressBookCollectionLocationOk",
        }
    }
}

impl Condition {
    pub fn display_name(&self) -> &'static str {
        match self {
            Condition::Base(base) => base.display_name(),
            Condition::Cal(cal) => cal.display_name(),
            Condition::Card(card) => card.display_name(),
        }
    }
}

#[cfg(test)]
mod serde_impl {
    use super::Status;
    use hyper::StatusCode;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Status {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Serialize the status code as a u16
            serializer.serialize_u16(self.0.as_u16())
        }
    }

    impl<'de> Deserialize<'de> for Status {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            // Deserialize as u16
            let status_value = u16::deserialize(deserializer)?;

            // Convert u16 to StatusCode
            let status_code = StatusCode::try_from(status_value).map_err(|_| {
                serde::de::Error::custom(format!("Invalid status code: {}", status_value))
            })?;

            Ok(Status(status_code))
        }
    }
}
