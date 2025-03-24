/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
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
    Namespace,
};

pub struct MultiStatus {
    pub namespace: Namespace,
    pub response: List<Response>,
    pub response_description: Option<ResponseDescription>,
    pub sync_token: Option<SyncToken>,
}

pub struct Response {
    pub href: Href,
    pub typ: ResponseType,
    pub error: Option<Condition>,
    pub response_description: Option<ResponseDescription>,
    pub location: Option<Location>,
}

pub enum ResponseType {
    PropStat(List<PropStat>),
    Status { href: List<Href>, status: Status },
}

#[repr(transparent)]
pub struct Status(pub StatusCode);

#[repr(transparent)]
pub struct Location(pub Href);

#[repr(transparent)]
pub struct ResponseDescription(pub String);

#[repr(transparent)]
pub struct SyncToken(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Href(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct List<T: Display>(pub Vec<T>);

pub struct MkColResponse {
    pub namespace: Namespace,
    pub propstat: List<PropStat>,
}

pub struct PropStat {
    pub prop: Prop,
    pub status: Status,
    pub error: Option<Condition>,
    pub response_description: Option<ResponseDescription>,
}

#[repr(transparent)]
pub struct Prop(pub List<DavPropertyValue>);

pub struct PropResponse {
    pub namespace: Namespace,
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
    pub namespace: Namespace,
    pub properties: List<PrincipalSearchProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalSearchProperty {
    pub name: DavProperty,
    pub description: String,
}

pub struct ErrorResponse {
    pub namespace: Namespace,
    pub error: Condition,
}

pub enum Condition {
    Base(BaseCondition),
    Cal(CalCondition),
    Card(CardCondition),
}

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

pub struct Resource {
    pub href: Href,
    pub privilege: Privilege,
}

pub enum CalCondition {
    CalendarCollectionLocationOk,
    ValidCalendarData,
    ValidFilter,
    ValidCalendarObjectResource,
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

pub enum CardCondition {
    SupportedAddressData,
    SupportedAddressDataConversion,
    SupportedFilter(Vec<Filter<(), VCardProperty, VCardParameterName>>),
    SupportedCollation(String),
    ValidAddressData,
    NoUidConflict(Href),
    MaxResourceSize(u32),
    AddressBoolCollectionLocationOk,
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
