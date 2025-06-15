/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use compact_str::CompactString;
use utils::map::bitmap::BitmapItem;

use super::{property::Property, type_state::DataType};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
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
    AddressBook = 10,
    ContactCard = 11,
    FileNode = 12,
    #[default]
    None = 13,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SyncCollection {
    Email = 0,
    Thread = 1,
    Calendar = 2,
    AddressBook = 3,
    FileNode = 4,
    Identity = 5,
    EmailSubmission = 6,
    SieveScript = 7,
    #[default]
    None = 8,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum VanishedCollection {
    Email = 251,
    Calendar = 252,
    AddressBook = 253,
    FileNode = 254,
}

impl Collection {
    pub fn main_collection(&self) -> Collection {
        match self {
            Collection::Email => Collection::Mailbox,
            Collection::CalendarEvent => Collection::Calendar,
            Collection::ContactCard => Collection::AddressBook,
            _ => *self,
        }
    }

    pub fn parent_collection(&self) -> Option<Collection> {
        match self {
            Collection::Email => Some(Collection::Mailbox),
            Collection::CalendarEvent => Some(Collection::Calendar),
            Collection::ContactCard => Some(Collection::AddressBook),
            Collection::FileNode => Some(Collection::FileNode),
            _ => None,
        }
    }

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

impl SyncCollection {
    pub fn collection(&self, is_container: bool) -> Collection {
        match self {
            SyncCollection::Email => {
                if is_container {
                    Collection::Mailbox
                } else {
                    Collection::Email
                }
            }
            SyncCollection::Thread => Collection::Thread,
            SyncCollection::Calendar => {
                if is_container {
                    Collection::Calendar
                } else {
                    Collection::CalendarEvent
                }
            }
            SyncCollection::AddressBook => {
                if is_container {
                    Collection::AddressBook
                } else {
                    Collection::ContactCard
                }
            }
            SyncCollection::FileNode => Collection::FileNode,
            SyncCollection::Identity => Collection::Identity,
            SyncCollection::EmailSubmission => Collection::EmailSubmission,
            SyncCollection::SieveScript => Collection::SieveScript,
            SyncCollection::None => Collection::None,
        }
    }

    pub fn vanished_collection(&self) -> Option<VanishedCollection> {
        match self {
            SyncCollection::Email => Some(VanishedCollection::Email),
            SyncCollection::Calendar => Some(VanishedCollection::Calendar),
            SyncCollection::AddressBook => Some(VanishedCollection::AddressBook),
            SyncCollection::FileNode => Some(VanishedCollection::FileNode),
            _ => None,
        }
    }
}

impl From<Collection> for SyncCollection {
    fn from(v: Collection) -> Self {
        match v {
            Collection::Email => SyncCollection::Email,
            Collection::Mailbox => SyncCollection::Email,
            Collection::Thread => SyncCollection::Thread,
            Collection::Identity => SyncCollection::Identity,
            Collection::EmailSubmission => SyncCollection::EmailSubmission,
            Collection::SieveScript => SyncCollection::SieveScript,
            Collection::PushSubscription => SyncCollection::None,
            Collection::Principal => SyncCollection::None,
            Collection::Calendar => SyncCollection::Calendar,
            Collection::CalendarEvent => SyncCollection::Calendar,
            Collection::AddressBook => SyncCollection::AddressBook,
            Collection::ContactCard => SyncCollection::AddressBook,
            Collection::FileNode => SyncCollection::FileNode,
            _ => SyncCollection::None,
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
            10 => Collection::AddressBook,
            11 => Collection::ContactCard,
            12 => Collection::FileNode,
            _ => Collection::None,
        }
    }
}

impl From<u8> for SyncCollection {
    fn from(v: u8) -> Self {
        match v {
            0 => SyncCollection::Email,
            1 => SyncCollection::Thread,
            2 => SyncCollection::Calendar,
            3 => SyncCollection::AddressBook,
            4 => SyncCollection::FileNode,
            5 => SyncCollection::Identity,
            6 => SyncCollection::EmailSubmission,
            7 => SyncCollection::SieveScript,
            _ => SyncCollection::None,
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
            10 => Collection::AddressBook,
            11 => Collection::ContactCard,
            12 => Collection::FileNode,
            _ => Collection::None,
        }
    }
}

impl From<Collection> for u8 {
    fn from(v: Collection) -> Self {
        v as u8
    }
}

impl From<SyncCollection> for u8 {
    fn from(v: SyncCollection) -> Self {
        v as u8
    }
}

impl From<VanishedCollection> for u8 {
    fn from(v: VanishedCollection) -> Self {
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
            "addressBook" => Collection::AddressBook,
            "contactCard" => Collection::ContactCard,
            "fileNode" => Collection::FileNode,
        )
        .ok_or(())
    }
}

impl From<Collection> for trc::Value {
    fn from(value: Collection) -> Self {
        trc::Value::String(CompactString::const_new(value.as_str()))
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

impl SyncCollection {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncCollection::Email => "email",
            SyncCollection::Thread => "thread",
            SyncCollection::Calendar => "calendar",
            SyncCollection::AddressBook => "addressBook",
            SyncCollection::FileNode => "fileNode",
            SyncCollection::Identity => "identity",
            SyncCollection::EmailSubmission => "emailSubmission",
            SyncCollection::SieveScript => "sieveScript",
            SyncCollection::None => "",
        }
    }
}
