/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;

use calcard::icalendar::ICalendar;
use dav_proto::schema::request::DeadProperty;
use jmap_proto::types::{acl::Acl, value::AclGrant};
use store::{SERIALIZE_OBJ_14_V1, SERIALIZE_OBJ_16_V1, SerializedVersion, ahash};
use utils::map::vec_map::VecMap;

use crate::DavName;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Calendar {
    pub name: String,
    pub preferences: HashMap<u32, CalendarPreferences, ahash::RandomState>,
    pub acls: Vec<AclGrant>,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarPreferences {
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub is_subscribed: bool,
    pub is_default: bool,
    pub is_visible: bool,
    pub include_in_availability: IncludeInAvailability,
    pub default_alerts_with_time: HashMap<String, ICalendar, ahash::RandomState>,
    pub default_alerts_without_time: HashMap<String, ICalendar, ahash::RandomState>,
    pub time_zone: Timezone,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEvent {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub event: ICalendar,
    pub user_properties: VecMap<u32, ICalendar>,
    pub may_invite_self: bool,
    pub may_invite_others: bool,
    pub hide_attendees: bool,
    pub is_draft: bool,
    pub dead_properties: DeadProperty,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub enum Timezone {
    IANA(String),
    Custom(ICalendar),
    #[default]
    Default,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub enum IncludeInAvailability {
    All,
    Attending,
    #[default]
    None,
}

pub enum CalendarRight {
    ReadFreeBusy,
    ReadItems,
    WriteAll,
    WriteOwn,
    UpdatePrivate,
    RSVP,
    Share,
    Delete,
}

impl TryFrom<Acl> for CalendarRight {
    type Error = Acl;

    fn try_from(value: Acl) -> Result<Self, Self::Error> {
        match value {
            Acl::ReadFreeBusy => Ok(CalendarRight::ReadFreeBusy),
            Acl::ReadItems => Ok(CalendarRight::ReadItems),
            Acl::Modify => Ok(CalendarRight::WriteAll),
            Acl::ModifyItemsOwn => Ok(CalendarRight::WriteOwn),
            Acl::ModifyPrivateProperties => Ok(CalendarRight::UpdatePrivate),
            Acl::RSVP => Ok(CalendarRight::RSVP),
            Acl::Share => Ok(CalendarRight::Share),
            Acl::Delete => Ok(CalendarRight::Delete),
            _ => Err(value),
        }
    }
}

impl From<CalendarRight> for Acl {
    fn from(value: CalendarRight) -> Self {
        match value {
            CalendarRight::ReadFreeBusy => Acl::ReadFreeBusy,
            CalendarRight::ReadItems => Acl::ReadItems,
            CalendarRight::WriteAll => Acl::Modify,
            CalendarRight::WriteOwn => Acl::ModifyItemsOwn,
            CalendarRight::UpdatePrivate => Acl::ModifyPrivateProperties,
            CalendarRight::RSVP => Acl::RSVP,
            CalendarRight::Share => Acl::Share,
            CalendarRight::Delete => Acl::Delete,
        }
    }
}

impl SerializedVersion for Calendar {
    fn serialize_version() -> u8 {
        SERIALIZE_OBJ_14_V1
    }
}

impl SerializedVersion for CalendarEvent {
    fn serialize_version() -> u8 {
        SERIALIZE_OBJ_16_V1
    }
}

impl ArchivedCalendar {
    pub fn preferences(&self, account_id: u32) -> Option<&ArchivedCalendarPreferences> {
        if self.preferences.len() == 1 {
            self.preferences.values().next()
        } else {
            self.preferences
                .get(&rkyv::rend::u32_le::from_native(account_id))
                .or_else(|| self.preferences.values().next())
        }
    }
}
