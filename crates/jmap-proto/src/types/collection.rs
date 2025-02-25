/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use utils::map::bitmap::BitmapItem;

use super::{property::Property, type_state::DataType};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum Collection {
    Email = 0,
    Mailbox = 1,
    Thread = 2,
    Identity = 3,
    EmailSubmission = 4,
    SieveScript = 5,
    PushSubscription = 6,
    Principal = 7,
    Calendar = 8,
    CalendarEvent = 9,
    CalendarEventNotification = 10,
    AddressBook = 11,
    ContactCard = 12,
    FileNode = 13,
    None = 14,
}

impl Collection {
    pub fn child_collection(&self) -> Option<Collection> {
        match self {
            Collection::Mailbox => Some(Collection::Email),
            Collection::Calendar => Some(Collection::CalendarEvent),
            Collection::AddressBook => Some(Collection::ContactCard),
            Collection::FileNode => Some(Collection::FileNode),
            _ => None,
        }
    }

    pub fn parent_property(&self) -> Option<Property> {
        match self {
            Collection::Email => Some(Property::MailboxIds),
            Collection::CalendarEvent => Some(Property::ParentId),
            Collection::ContactCard => Some(Property::ParentId),
            Collection::FileNode => Some(Property::ParentId),
            _ => None,
        }
    }
}

impl From<u8> for Collection {
    fn from(v: u8) -> Self {
        match v {
            0 => Collection::Email,
            1 => Collection::Mailbox,
            2 => Collection::Thread,
            3 => Collection::Identity,
            4 => Collection::EmailSubmission,
            5 => Collection::SieveScript,
            6 => Collection::PushSubscription,
            7 => Collection::Principal,
            8 => Collection::Calendar,
            9 => Collection::CalendarEvent,
            10 => Collection::CalendarEventNotification,
            11 => Collection::AddressBook,
            12 => Collection::ContactCard,
            13 => Collection::FileNode,
            _ => Collection::None,
        }
    }
}

impl From<u64> for Collection {
    fn from(v: u64) -> Self {
        match v {
            0 => Collection::Email,
            1 => Collection::Mailbox,
            2 => Collection::Thread,
            3 => Collection::Identity,
            4 => Collection::EmailSubmission,
            5 => Collection::SieveScript,
            6 => Collection::PushSubscription,
            7 => Collection::Principal,
            8 => Collection::Calendar,
            9 => Collection::CalendarEvent,
            10 => Collection::CalendarEventNotification,
            11 => Collection::AddressBook,
            12 => Collection::ContactCard,
            13 => Collection::FileNode,
            _ => Collection::None,
        }
    }
}

impl From<Collection> for u8 {
    fn from(v: Collection) -> Self {
        v as u8
    }
}

impl From<Collection> for u64 {
    fn from(collection: Collection) -> u64 {
        collection as u64
    }
}

impl TryFrom<Collection> for DataType {
    type Error = ();

    fn try_from(value: Collection) -> Result<Self, Self::Error> {
        match value {
            Collection::Email => Ok(DataType::Email),
            Collection::Mailbox => Ok(DataType::Mailbox),
            Collection::Thread => Ok(DataType::Thread),
            Collection::Identity => Ok(DataType::Identity),
            Collection::EmailSubmission => Ok(DataType::EmailSubmission),
            Collection::SieveScript => Ok(DataType::SieveScript),
            Collection::PushSubscription => Ok(DataType::PushSubscription),
            _ => Err(()),
        }
    }
}

impl Display for Collection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Collection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Collection::PushSubscription => "pushSubscription",
            Collection::Email => "email",
            Collection::Mailbox => "mailbox",
            Collection::Thread => "thread",
            Collection::Identity => "identity",
            Collection::EmailSubmission => "emailSubmission",
            Collection::SieveScript => "sieveScript",
            Collection::Principal => "principal",
            Collection::Calendar => "calendar",
            Collection::CalendarEvent => "calendarEvent",
            Collection::CalendarEventNotification => "calendarEventNotification",
            Collection::AddressBook => "addressBook",
            Collection::ContactCard => "contactCard",
            Collection::FileNode => "fileNode",
            Collection::None => "",
        }
    }
}

impl FromStr for Collection {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hashify::tiny_map!(s.as_bytes(),
            "pushSubscription" => Collection::PushSubscription,
            "email" => Collection::Email,
            "mailbox" => Collection::Mailbox,
            "thread" => Collection::Thread,
            "identity" => Collection::Identity,
            "emailSubmission" => Collection::EmailSubmission,
            "sieveScript" => Collection::SieveScript,
            "principal" => Collection::Principal,
            "calendar" => Collection::Calendar,
            "calendarEvent" => Collection::CalendarEvent,
            "calendarEventNotification" => Collection::CalendarEventNotification,
            "addressBook" => Collection::AddressBook,
            "contactCard" => Collection::ContactCard,
            "fileNode" => Collection::FileNode,
        )
        .ok_or(())
    }
}

impl From<Collection> for trc::Value {
    fn from(value: Collection) -> Self {
        trc::Value::Static(value.as_str())
    }
}

impl BitmapItem for Collection {
    fn max() -> u64 {
        Collection::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, Collection::None)
    }
}
