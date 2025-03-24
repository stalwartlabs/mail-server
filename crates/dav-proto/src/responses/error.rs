/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::schema::{
    response::{BaseCondition, CalCondition, CardCondition, Condition, ErrorResponse},
    Namespace,
};

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:error {}>", self.namespace)?;

        match &self.error {
            Condition::Base(e) => e.fmt(f)?,
            Condition::Cal(e) => e.fmt(f)?,
            Condition::Card(e) => e.fmt(f)?,
        }

        write!(f, "</D:error>")
    }
}

impl Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:error>")?;

        match self {
            Condition::Base(e) => e.fmt(f)?,
            Condition::Cal(e) => e.fmt(f)?,
            Condition::Card(e) => e.fmt(f)?,
        }

        write!(f, "</D:error>")
    }
}

impl Display for BaseCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseCondition::NoConflictingLock(items) => {
                write!(f, "<D:no-conflicting-lock>{items}</D:no-conflicting-lock>")
            }
            BaseCondition::LockTokenSubmitted(items) => write!(
                f,
                "<D:lock-token-submitted>{items}</D:lock-token-submitted>"
            ),
            BaseCondition::LockTokenMatchesRequestUri => {
                write!(f, "<D:lock-token-matches-request-uri/>")
            }
            BaseCondition::CannotModifyProtectedProperty => {
                write!(f, "<D:cannot-modify-protected-property/>")
            }
            BaseCondition::NoExternalEntities => write!(f, "<D:no-external-entities/>"),
            BaseCondition::PreservedLiveProperties => write!(f, "<D:preserved-live-properties/>"),
            BaseCondition::PropFindFiniteDepth => write!(f, "<D:propfind-finite-depth/>"),
            BaseCondition::ResourceMustBeNull => write!(f, "<D:resource-must-be-null/>"),
            BaseCondition::NeedPrivileges(resources) => {
                write!(f, "<D:need-privileges>{resources}</D:need-privileges>")
            }
            BaseCondition::NumberOfMatchesWithinLimit => {
                write!(f, "<D:number-of-matches-within-limits/>")
            }
            BaseCondition::QuotaNotExceeded => write!(f, "<D:quota-not-exceeded/>"),
            BaseCondition::ValidResourceType => write!(f, "<D:valid-resourcetype/>"),
            BaseCondition::ValidSyncToken => write!(f, "<D:valid-sync-token/>"),
            BaseCondition::NoAceConflict => write!(f, "<D:no-ace-conflict/>"),
            BaseCondition::NoProtectedAceConflict => write!(f, "<D:no-protected-ace-conflict/>"),
            BaseCondition::NoInheritedAceConflict => write!(f, "<D:no-inherited-ace-conflict/>"),
            BaseCondition::LimitedNumberOfAces => write!(f, "<D:limited-number-of-aces/>"),
            BaseCondition::DenyBeforeGrant => write!(f, "<D:deny-before-grant/>"),
            BaseCondition::GrantOnly => write!(f, "<D:grant-only/>"),
            BaseCondition::NoInvert => write!(f, "<D:no-invert/>"),
            BaseCondition::NoAbstract => write!(f, "<D:no-abstract/>"),
            BaseCondition::NotSupportedPrivilege => write!(f, "<D:not-supported-privilege/>"),
            BaseCondition::MissingRequiredPrincipal => write!(f, "<D:missing-required-principal/>"),
            BaseCondition::RecognizedPrincipal => write!(f, "<D:recognized-principal/>"),
            BaseCondition::AllowedPrincipal => write!(f, "<D:allowed-principal/>"),
        }
    }
}

impl Display for CalCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalCondition::CalendarCollectionLocationOk => {
                write!(f, "<C:calendar-collection-location-ok/>")
            }
            CalCondition::ValidCalendarData => write!(f, "<C:valid-calendar-data/>"),
            CalCondition::ValidFilter => write!(f, "<C:valid-filter/>"),
            CalCondition::ValidCalendarObjectResource => {
                write!(f, "<C:valid-calendar-object-resource/>")
            }
            CalCondition::NoUidConflict(uid) => {
                write!(f, "<C:no-uid-conflict>{uid}</C:no-uid-conflict>")
            }
            CalCondition::InitializeCalendarCollection => {
                write!(f, "<C:initialize-calendar-collection/>")
            }
            CalCondition::SupportedCalendarData => write!(f, "<C:supported-calendar-data/>"),
            CalCondition::SupportedFilter(_) => write!(f, "<C:supported-filter/>"),
            CalCondition::SupportedCollation(c) => {
                write!(f, "<C:supported-collation>{c}</C:supported-collation>")
            }
            CalCondition::MinDateTime => write!(f, "<C:min-date-time/>"),
            CalCondition::MaxDateTime => write!(f, "<C:max-date-time/>"),
            CalCondition::MaxResourceSize(l) => {
                write!(f, "<C:max-resource-size>{l}</C:max-resource-size>")
            }
            CalCondition::MaxInstances => write!(f, "<C:max-instances/>"),
            CalCondition::MaxAttendeesPerInstance => write!(f, "<C:max-attendees-per-instance/>"),
        }
    }
}

impl Display for CardCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardCondition::SupportedAddressData => write!(f, "<C:supported-address-data/>"),
            CardCondition::SupportedAddressDataConversion => {
                write!(f, "<C:supported-address-data-conversion/>")
            }
            CardCondition::SupportedFilter(_) => write!(f, "<C:supported-filter/>"),
            CardCondition::SupportedCollation(c) => {
                write!(f, "<C:supported-collation>{c}</C:supported-collation>")
            }
            CardCondition::ValidAddressData => write!(f, "<C:valid-address-data/>"),
            CardCondition::NoUidConflict(uid) => {
                write!(f, "<C:no-uid-conflict>{uid}</C:no-uid-conflict>")
            }
            CardCondition::MaxResourceSize(l) => {
                write!(f, "<C:max-resource-size>{l}</C:max-resource-size>")
            }
            CardCondition::AddressBoolCollectionLocationOk => {
                write!(f, "<C:addressbook-collection-location-ok/>")
            }
        }
    }
}

impl From<CalCondition> for Condition {
    fn from(error: CalCondition) -> Self {
        Condition::Cal(error)
    }
}

impl From<CardCondition> for Condition {
    fn from(error: CardCondition) -> Self {
        Condition::Card(error)
    }
}

impl From<BaseCondition> for Condition {
    fn from(error: BaseCondition) -> Self {
        Condition::Base(error)
    }
}

impl ErrorResponse {
    pub fn new(error: impl Into<Condition>) -> Self {
        ErrorResponse {
            namespace: Namespace::Dav,
            error: error.into(),
        }
    }

    pub fn with_namespace(mut self, namespace: impl Into<Namespace>) -> Self {
        self.namespace = namespace.into();
        self
    }
}
