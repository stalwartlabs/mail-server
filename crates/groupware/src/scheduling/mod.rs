/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarDuration, ICalendarMethod,
        ICalendarParticipationRole, ICalendarParticipationStatus, ICalendarPeriod,
        ICalendarProperty, ICalendarRecurrenceRule, ICalendarScheduleForceSendValue,
        ICalendarStatus, ICalendarUserTypes, Uri,
    },
};
use ahash::{AHashMap, AHashSet};
use std::{fmt::Display, hash::Hash};

pub mod attendee;
pub mod event_cancel;
pub mod event_create;
pub mod event_update;
pub mod inbound;
pub mod itip;
pub mod organizer;
pub mod snapshot;

pub struct ItipSnapshots<'x> {
    pub organizer: Organizer<'x>,
    pub uid: &'x str,
    pub sequence: Option<i64>,
    pub components: AHashMap<InstanceId<'x>, ItipSnapshot<'x>>,
}

#[derive(Debug, Default)]
pub struct ItipSnapshot<'x> {
    pub comp_id: u16,
    pub attendees: AHashSet<Attendee<'x>>,
    pub dtstamp: Option<&'x PartialDateTime>,
    pub entries: AHashSet<ItipEntry<'x>>,
    pub request_status: Vec<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ItipEntry<'x> {
    pub name: &'x ICalendarProperty,
    pub value: ItipEntryValue<'x>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ItipEntryValue<'x> {
    DateTime(UnresolvedDateTime<'x>),
    Period(&'x ICalendarPeriod),
    Duration(&'x ICalendarDuration),
    Status(&'x ICalendarStatus),
    RRule(&'x ICalendarRecurrenceRule),
    Text(&'x str),
    Integer(i64),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct UnresolvedDateTime<'x> {
    pub date: &'x PartialDateTime,
    pub tz_id: Option<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum InstanceId<'x> {
    Main,
    Recurrence(RecurrenceId<'x>),
}

#[derive(Debug)]
pub struct RecurrenceId<'x> {
    pub entry_id: u16,
    pub date: UnresolvedDateTime<'x>,
    pub this_and_future: bool,
}

#[derive(Debug)]
pub struct Attendee<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub part_stat: Option<&'x ICalendarParticipationStatus>,
    pub delegated_from: Vec<Email>,
    pub delegated_to: Vec<Email>,
    pub role: Option<&'x ICalendarParticipationRole>,
    pub cu_type: Option<&'x ICalendarUserTypes>,
    pub sent_by: Option<Email>,
    pub rsvp: Option<bool>,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Organizer<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Email {
    pub email: String,
    pub is_local: bool,
}

#[derive(Debug)]
pub struct SchedulingInfo {
    pub sequence: u32,
    pub tag: u32,
}

#[derive(Debug)]
pub enum ItipError {
    NoSchedulingInfo,
    OtherSchedulingAgent,
    NotOrganizer,
    NotOrganizerNorAttendee,
    NothingToSend,
    MissingUid,
    MultipleUid,
    MultipleSequence,
    MultipleOrganizer,
    MultipleObjectTypes,
    MultipleObjectInstances,
    ChangeNotAllowed,
}

pub struct ItipMessage {
    pub method: ICalendarMethod,
    pub from: String,
    pub to: Vec<String>,
    pub changed_properties: Vec<ICalendarProperty>,
    pub message: ICalendar,
}

impl ICalendarComponentType {
    pub fn is_scheduling_object(&self) -> bool {
        matches!(
            self,
            ICalendarComponentType::VEvent
                | ICalendarComponentType::VTodo
                | ICalendarComponentType::VJournal
                | ICalendarComponentType::VFreebusy
        )
    }
}

impl ItipSnapshot<'_> {
    pub fn has_local_attendee(&self) -> bool {
        self.attendees
            .iter()
            .any(|attendee| attendee.email.is_local)
    }

    pub fn local_attendee(&self) -> Option<&Attendee<'_>> {
        self.attendees
            .iter()
            .find(|attendee| attendee.email.is_local)
    }
}

impl Attendee<'_> {
    pub fn send_scheduling_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self.part_stat.is_none_or(|part_stat| {
                    part_stat != &ICalendarParticipationStatus::NeedsAction
                }))
    }
}

impl Email {
    pub fn new(email: &str, local_addresses: &[&str]) -> Option<Self> {
        email.contains('@').then(|| {
            let email = email.trim().trim_start_matches("mailto:").to_lowercase();
            let is_local = local_addresses.contains(&email.as_str());
            Email { email, is_local }
        })
    }

    pub fn from_uri(uri: &Uri, local_addresses: &[&str]) -> Option<Self> {
        if let Uri::Location(uri) = uri {
            Email::new(uri.as_str(), local_addresses)
        } else {
            None
        }
    }
}

impl PartialEq for Attendee<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.part_stat == other.part_stat
            && self.delegated_from == other.delegated_from
            && self.delegated_to == other.delegated_to
            && self.role == other.role
            && self.cu_type == other.cu_type
            && self.sent_by == other.sent_by
    }
}

impl Eq for Attendee<'_> {}

impl Hash for Attendee<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.part_stat.hash(state);
        self.delegated_from.hash(state);
        self.delegated_to.hash(state);
        self.role.hash(state);
        self.cu_type.hash(state);
        self.sent_by.hash(state);
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mailto:{}", self.email)
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

impl Eq for Email {}

impl PartialEq for RecurrenceId<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.date == other.date && self.this_and_future == other.this_and_future
    }
}

impl Eq for RecurrenceId<'_> {}

impl Hash for RecurrenceId<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.date.hash(state);
        self.this_and_future.hash(state);
    }
}
