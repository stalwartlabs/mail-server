/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{common::timezone::Tz, icalendar::ICalendar};
use common::{DavName, Server};
use dav_proto::schema::request::DeadProperty;
use groupware::calendar::{
    AlarmDelta, CalendarEvent, CalendarEventData, ComponentTimeRange, UserProperties,
};
use jmap_proto::types::{collection::Collection, property::Property};
use store::{
    Serialize,
    rand::{self, seq::SliceRandom},
    write::{Archiver, BatchBuilder, serialize::rkyv_deserialize},
};
use trc::AddContext;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventV1 {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub data: CalendarEventDataV1,
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
pub struct CalendarEventDataV1 {
    pub event: ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub alarms: Box<[AlarmV1]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AlarmV1 {
    pub comp_id: u16,
    pub alarms: Box<[AlarmDelta]>,
}

pub(crate) async fn migrate_calendar_events(server: &Server) -> trc::Result<()> {
    // Obtain email ids
    let account_ids = server
        .get_document_ids(u32::MAX, Collection::Principal)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_accounts = account_ids.len();
    if num_accounts == 0 {
        return Ok(());
    }

    let mut account_ids = account_ids.into_iter().collect::<Vec<_>>();

    account_ids.shuffle(&mut rand::rng());

    for account_id in account_ids {
        let document_ids = server
            .get_document_ids(account_id, Collection::CalendarEvent)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        if document_ids.is_empty() {
            continue;
        }
        let mut num_migrated = 0;

        for document_id in document_ids.iter() {
            let Some(archive) = server
                .get_archive(account_id, Collection::CalendarEvent, document_id)
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };

            match archive.unarchive_untrusted::<CalendarEventV1>() {
                Ok(event) => {
                    let event = rkyv_deserialize::<_, CalendarEventV1>(event).unwrap();
                    let mut next_email_alarm = None;
                    let new_event = CalendarEvent {
                        names: event.names,
                        display_name: event.display_name,
                        data: CalendarEventData::new(
                            event.data.event,
                            Tz::Floating,
                            server.core.groupware.max_ical_instances,
                            &mut next_email_alarm,
                        ),
                        user_properties: event.user_properties,
                        flags: event.flags,
                        dead_properties: event.dead_properties,
                        size: event.size,
                        created: event.created,
                        modified: event.modified,
                    };
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::CalendarEvent)
                        .update_document(document_id)
                        .set(
                            Property::Value,
                            Archiver::new(new_event)
                                .serialize()
                                .caused_by(trc::location!())?,
                        );
                    if let Some(next_email_alarm) = next_email_alarm {
                        next_email_alarm.write_task(&mut batch);
                    }
                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                    num_migrated += 1;
                }
                Err(err) => {
                    if archive.unarchive_untrusted::<CalendarEvent>().is_err() {
                        return Err(err.caused_by(trc::location!()));
                    }
                }
            }
        }

        if num_migrated > 0 {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details =
                    format!("Migrated {num_migrated} Calendar Events for account {account_id}")
            );
        }
    }

    Ok(())
}
