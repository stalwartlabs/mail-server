/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::DestroyArchive;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use jmap_proto::types::collection::Collection;
use store::write::{Archive, BatchBuilder, now};
use trc::AddContext;

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, Calendar, CalendarEvent, CalendarPreferences,
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
            .map(|b| b.commit_point())
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
    pub async fn delete_with_events(
        self,
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
        children_ids: Vec<u32>,
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
                    batch,
                )?;
            }
        }

        self.delete(access_token, account_id, document_id, batch)
    }

    pub fn delete(
        self,
        access_token: &AccessToken,
        account_id: u32,
        document_id: u32,
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
            .caused_by(trc::location!())?
            .commit_point();

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
                batch
                    .delete_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_tenant_id(access_token)
                            .with_current(event),
                    )
                    .caused_by(trc::location!())?;
            }

            batch.commit_point();
        }

        Ok(())
    }
}
