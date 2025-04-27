/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod dates;
pub mod index;
pub mod storage;

use crate::DavName;
use calcard::icalendar::ICalendar;
use dav_proto::schema::request::DeadProperty;
use jmap_proto::types::{acl::Acl, value::AclGrant};
use store::{SERIALIZE_CALENDAR_V1, SERIALIZE_CALENDAREVENT_V1, SerializedVersion};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Calendar {
    pub name: String,
    pub preferences: Vec<CalendarPreferences>,
    pub default_alerts: Vec<DefaultAlert>,
    pub acls: Vec<AclGrant>,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
}

pub const CALENDAR_SUBSCRIBED: u16 = 1;
pub const CALENDAR_DEFAULT: u16 = 1 << 1;
pub const CALENDAR_VISIBLE: u16 = 1 << 2;
pub const CALENDAR_AVAILABILITY_ALL: u16 = 1 << 3;
pub const CALENDAR_AVAILABILITY_ATTENDING: u16 = 1 << 4;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarPreferences {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub flags: u16,
    pub time_zone: Timezone,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct DefaultAlert {
    pub account_id: u32,
    pub id: String,
    pub alert: ICalendar,
    pub with_time: bool,
}

pub const EVENT_INVITE_SELF: u16 = 1;
pub const EVENT_INVITE_OTHERS: u16 = 1 << 1;
pub const EVENT_HIDE_ATTENDEES: u16 = 1 << 2;
pub const EVENT_DRAFT: u16 = 1 << 3;
pub const EVENT_ORIGIN: u16 = 1 << 4;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEvent {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub data: CalendarEventData,
    pub user_properties: Vec<UserProperties>,
    pub flags: u16,
    pub dead_properties: DeadProperty,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventData {
    pub event: ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ComponentTimeRange {
    pub id: u16,
    pub start_tz: u16,
    pub end_tz: u16,
    pub duration: i32,
    pub instances: Box<[u8]>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct UserProperties {
    pub account_id: u32,
    pub properties: ICalendar,
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
        SERIALIZE_CALENDAR_V1
    }
}

impl SerializedVersion for CalendarEvent {
    fn serialize_version() -> u8 {
        SERIALIZE_CALENDAREVENT_V1
    }
}

impl Calendar {
    pub fn preferences(&self, account_id: u32) -> &CalendarPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }

    pub fn preferences_mut(&mut self, account_id: u32) -> &mut CalendarPreferences {
        if self.preferences.len() == 1 {
            &mut self.preferences[0]
        } else {
            let idx = self
                .preferences
                .iter()
                .position(|p| p.account_id == account_id)
                .unwrap_or(0);
            &mut self.preferences[idx]
        }
    }
}

impl ArchivedCalendar {
    pub fn preferences(&self, account_id: u32) -> &ArchivedCalendarPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }
}
