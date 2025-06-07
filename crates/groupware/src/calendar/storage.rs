/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavResourceName, DestroyArchive, RFC_3986};
use calcard::common::timezone::Tz;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::collection::{Collection, VanishedCollection};
use store::{
    U16_LEN, U64_LEN,
    write::{Archive, BatchBuilder, TaskQueueClass, ValueClass, key::KeySerializer, now},
};
use trc::AddContext;

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, Calendar, CalendarEvent, CalendarPreferences,
    alarm::CalendarAlarm,
};

impl CalendarEvent {
    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        event: Archive<&ArchivedCalendarEvent>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        let mut new_event = self;

        // Build event
        new_event.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(event)
                    .with_changes(new_event)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        next_alarm: Option<CalendarAlarm>,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build event
        let mut event = self;
        let now = now() as i64;
        event.modified = now;
        event.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(event)
                    .with_tenant_id(access_token),
            )
            .map(|batch| {
                if let Some(next_alarm) = next_alarm {
                    next_alarm.write_task(batch);
                }

                batch.commit_point()
            })
    }
}

impl Calendar {
    pub fn insert<'x>(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address calendar
        let mut calendar = self;
        let now = now() as i64;
        calendar.modified = now;
        calendar.created = now;

        if calendar.preferences.is_empty() {
            calendar.preferences.push(CalendarPreferences {
                account_id,
                name: "default".to_string(),
                ..Default::default()
            });
        }

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .create_document(document_id)
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(calendar)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }

    pub fn update<'x>(
        self,
        access_token: &AccessToken,
        calendar: Archive<&ArchivedCalendar>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address calendar
        let mut new_calendar = self;
        new_calendar.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .update_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(calendar)
                    .with_changes(new_calendar)
                    .with_tenant_id(access_token),
            )
            .map(|b| b.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendar>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_with_events(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        children_ids: Vec<u32>,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Process deletions
        let calendar_id = document_id;
        for document_id in children_ids {
            if let Some(event_) = server
                .get_archive(account_id, Collection::CalendarEvent, document_id)
                .await?
            {
                DestroyArchive(
                    event_
                        .to_unarchived::<CalendarEvent>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    access_token,
                    account_id,
                    document_id,
                    calendar_id,
                    None,
                    batch,
                )?;
            }
        }

        self.delete(access_token, account_id, document_id, delete_path, batch)
    }

    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let calendar = self.0;
        // Delete calendar
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Calendar)
            .delete_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_tenant_id(access_token)
                    .with_current(calendar),
            )
            .caused_by(trc::location!())?;
        if let Some(delete_path) = delete_path {
            batch.log_vanished_item(VanishedCollection::Calendar, delete_path);
        }
        batch.commit_point();

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedCalendarEvent>> {
    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        calendar_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let event = self.0;
        if let Some(delete_idx) = event
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == calendar_id)
        {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::CalendarEvent);

            if event.inner.names.len() > 1 {
                // Unlink calendar id from event
                let mut new_event = event
                    .deserialize::<CalendarEvent>()
                    .caused_by(trc::location!())?;
                new_event.names.swap_remove(delete_idx);
                batch
                    .update_document(document_id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_tenant_id(access_token)
                            .with_current(event)
                            .with_changes(new_event),
                    )
                    .caused_by(trc::location!())?;
            } else {
                // Delete event
                batch.delete_document(document_id);

                // Remove next alarm if it exists
                if let Some(next_alarm) = event.inner.data.next_alarm(now() as i64, Tz::Floating) {
                    next_alarm.delete_task(batch);
                }

                batch
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_tenant_id(access_token)
                            .with_current(event),
                    )
                    .caused_by(trc::location!())?;
            }

            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::Calendar, delete_path);
            }

            batch.commit_point();
        }

        Ok(())
    }
}

impl CalendarAlarm {
    pub fn write_task(&self, batch: &mut BatchBuilder) {
        batch.set(
            ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
                due: self.alarm_time as u64,
                event_id: self.event_id,
                alarm_id: self.alarm_id,
            }),
            KeySerializer::new((U64_LEN * 2) + (U16_LEN * 2))
                .write(self.event_start as u64)
                .write(self.event_end as u64)
                .write(self.event_start_tz)
                .write(self.event_end_tz)
                .finalize(),
        );
    }

    pub fn delete_task(&self, batch: &mut BatchBuilder) {
        batch.clear(ValueClass::TaskQueue(TaskQueueClass::SendAlarm {
            due: self.alarm_time as u64,
            event_id: self.event_id,
            alarm_id: self.alarm_id,
        }));
    }
}

impl ArchivedCalendarEvent {
    pub async fn webcal_uri(
        &self,
        server: &Server,
        access_token: &AccessToken,
    ) -> trc::Result<String> {
        for event_name in self.names.iter() {
            if let Some(calendar_) = server
                .get_archive(
                    access_token.primary_id,
                    Collection::Calendar,
                    event_name.parent_id.to_native(),
                )
                .await
                .caused_by(trc::location!())?
            {
                let calendar = calendar_
                    .unarchive::<Calendar>()
                    .caused_by(trc::location!())?;
                return Ok(format!(
                    "webcal://{}{}/{}/{}/{}",
                    server.core.network.server_name,
                    DavResourceName::Cal.base_path(),
                    percent_encoding::utf8_percent_encode(&access_token.name, RFC_3986),
                    calendar.name,
                    event_name.name
                ));
            }
        }

        Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Event is not linked to any calendar"))
    }
}
