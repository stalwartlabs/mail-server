/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::index::{
    IndexItem, IndexValue, IndexableAndSerializableObject, IndexableObject,
};
use jmap_proto::types::{collection::SyncCollection, value::AclGrant};
use store::{SerializeInfallible, write::key::KeySerializer};

use crate::{IDX_NAME, IDX_TIME, IDX_UID};

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarPreferences, ArchivedDefaultAlert,
    ArchivedTimezone, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert, Timezone,
};

impl IndexableObject for Calendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        // Note: When adding a new value with index id above 0u8, tune `build_hierarchy`` to skip
        // this value during iteration.
        [
            IndexValue::Index {
                field: IDX_NAME,
                value: self.name.as_str().into(),
            },
            IndexValue::Index {
                field: IDX_TIME,
                value: self
                    .preferences
                    .first()
                    .and_then(|p| p.time_zone.tz())
                    .map(|tz| tz.as_id().serialize())
                    .into(),
            },
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.default_alerts.iter().map(|a| a.size()).sum::<usize>() as u32
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar.into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: IDX_NAME,
                value: self.name.as_str().into(),
            },
            IndexValue::Index {
                field: IDX_TIME,
                value: self
                    .preferences
                    .first()
                    .and_then(|p| p.time_zone.tz())
                    .map(|tz| tz.as_id().serialize())
                    .into(),
            },
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.default_alerts.iter().map(|a| a.size()).sum::<usize>() as u32
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar.into(),
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Calendar {}

impl IndexableObject for CalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::IndexList {
                field: IDX_NAME,
                value: self
                    .names
                    .iter()
                    .map(|v| IndexItem::Vec(v.serialize()))
                    .collect::<Vec<_>>(),
            },
            IndexValue::Index {
                field: IDX_UID,
                value: self.data.event.uids().next().into(),
            },
            IndexValue::Index {
                field: IDX_TIME,
                value: self
                    .data
                    .event_range()
                    .map(|(start, duration)| {
                        KeySerializer::new(std::mem::size_of::<i64>() + std::mem::size_of::<u32>())
                            .write(start as u64)
                            .write(duration)
                            .finalize()
                    })
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar.into(),
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::IndexList {
                field: IDX_NAME,
                value: self
                    .names
                    .iter()
                    .map(|v| IndexItem::Vec(v.serialize()))
                    .collect::<Vec<_>>(),
            },
            IndexValue::Index {
                field: IDX_UID,
                value: self.data.event.uids().next().into(),
            },
            IndexValue::Index {
                field: IDX_TIME,
                value: self
                    .data
                    .event_range()
                    .map(|(start, duration)| {
                        KeySerializer::new(std::mem::size_of::<i64>() + std::mem::size_of::<u32>())
                            .write(start as u64)
                            .write(duration)
                            .finalize()
                    })
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar.into(),
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEvent {}

impl CalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
    }
}

impl ArchivedCalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
    }
}

impl Timezone {
    pub fn size(&self) -> usize {
        match self {
            Timezone::IANA(_) => 2,
            Timezone::Custom(c) => c.size(),
            Timezone::Default => 0,
        }
    }
}

impl ArchivedTimezone {
    pub fn size(&self) -> usize {
        match self {
            ArchivedTimezone::IANA(_) => 2,
            ArchivedTimezone::Custom(c) => c.size(),
            ArchivedTimezone::Default => 0,
        }
    }
}

impl DefaultAlert {
    pub fn size(&self) -> usize {
        self.alert.size() + self.id.len()
    }
}

impl ArchivedDefaultAlert {
    pub fn size(&self) -> usize {
        self.alert.size() + self.id.len()
    }
}
