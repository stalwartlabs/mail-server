/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::schema::{
    response::{BaseCondition, CalCondition, CardCondition, Condition, ErrorResponse},
    Namespace, Namespaces,
};

impl Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><D:error {}>",
            self.namespaces
        )?;

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
                write!(f, "<A:calendar-collection-location-ok/>")
            }
            CalCondition::ValidCalendarData => write!(f, "<A:valid-calendar-data/>"),
            CalCondition::ValidFilter => write!(f, "<A:valid-filter/>"),
            CalCondition::ValidTimezone => write!(f, "<A:valid-timezone/>"),
            CalCondition::ValidCalendarObjectResource => {
                write!(f, "<A:valid-calendar-object-resource/>")
            }
            CalCondition::NoUidConflict(uid) => {
                write!(f, "<A:no-uid-conflict>{uid}</A:no-uid-conflict>")
            }
            CalCondition::InitializeCalendarCollection => {
                write!(f, "<A:initialize-calendar-collection/>")
            }
            CalCondition::SupportedCalendarData => write!(f, "<A:supported-calendar-data/>"),
            CalCondition::SupportedFilter(_) => write!(f, "<A:supported-filter/>"),
            CalCondition::SupportedCollation(c) => {
                write!(f, "<A:supported-collation>{c}</A:supported-collation>")
            }
            CalCondition::MinDateTime => write!(f, "<A:min-date-time/>"),
            CalCondition::MaxDateTime => write!(f, "<A:max-date-time/>"),
            CalCondition::MaxResourceSize(l) => {
                write!(f, "<A:max-resource-size>{l}</A:max-resource-size>")
            }
            CalCondition::MaxInstances => write!(f, "<A:max-instances/>"),
            CalCondition::MaxAttendeesPerInstance => write!(f, "<A:max-attendees-per-instance/>"),
        }
    }
}

impl Display for CardCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardCondition::SupportedAddressData => write!(f, "<B:supported-address-data/>"),
            CardCondition::SupportedAddressDataConversion => {
                write!(f, "<B:supported-address-data-conversion/>")
            }
            CardCondition::SupportedFilter(_) => write!(f, "<B:supported-filter/>"),
            CardCondition::SupportedCollation(c) => {
                write!(f, "<B:supported-collation>{c}</B:supported-collation>")
            }
            CardCondition::ValidAddressData => write!(f, "<B:valid-address-data/>"),
            CardCondition::NoUidConflict(uid) => {
                write!(f, "<B:no-uid-conflict>{uid}</B:no-uid-conflict>")
            }
            CardCondition::MaxResourceSize(l) => {
                write!(f, "<B:max-resource-size>{l}</B:max-resource-size>")
            }
            CardCondition::AddressBookCollectionLocationOk => {
                write!(f, "<B:addressbook-collection-location-ok/>")
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
            namespaces: Namespaces::default(),
            error: error.into(),
        }
    }

    pub fn with_namespace(mut self, namespace: impl Into<Namespace>) -> Self {
        self.namespaces.set(namespace.into());
        self
    }
}
