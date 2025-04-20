/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashSet;

use calcard::{
    Entry, Parser,
    icalendar::{ICalendar, ICalendarComponentType},
};
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{property::Rfc1123DateTime, response::CalCondition},
};
use groupware::{DavName, calendar::CalendarEvent, hierarchy::DavHierarchy};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use crate::{
    DavError, DavErrorCondition, DavMethod,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};

use super::assert_is_unique_uid;

pub(crate) trait CalendarUpdateRequestHandler: Sync + Send {
    fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        bytes: Vec<u8>,
        is_patch: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarUpdateRequestHandler for Server {
    async fn handle_calendar_update_request(
        &self,
        access_token: &AccessToken,
        headers: RequestHeaders<'_>,
        bytes: Vec<u8>,
        _is_patch: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, Collection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let resource_name = resource
            .resource
            .ok_or(DavError::Code(StatusCode::CONFLICT))?;

        if bytes.len() > self.core.dav.max_ical_size {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::MaxResourceSize(self.core.dav.max_ical_size as u32),
            )));
        }
        let ical_raw = std::str::from_utf8(&bytes).map_err(|_| {
            DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::SupportedCalendarData,
            ))
        })?;

        let ical = match Parser::new(ical_raw).entry() {
            Entry::ICalendar(ical) => ical,
            _ => {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::SupportedCalendarData,
                )));
            }
        };

        if let Some(resource) = resources.paths.by_name(resource_name) {
            if resource.is_container {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            let parent_id = resource.parent_id.unwrap();
            let document_id = resource.document_id;
            if !access_token.is_member(account_id)
                && !self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::Calendar,
                        parent_id,
                        Acl::ModifyItems,
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Update
            let event_ = self
                .get_archive(account_id, Collection::CalendarEvent, document_id)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            let event = event_
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Validate headers
            match self
                .validate_headers(
                    access_token,
                    &headers,
                    vec![ResourceState {
                        account_id,
                        collection: Collection::CalendarEvent,
                        document_id: Some(document_id),
                        etag: event.etag().into(),
                        path: resource_name,
                        ..Default::default()
                    }],
                    Default::default(),
                    DavMethod::PUT,
                )
                .await
            {
                Ok(_) => {}
                Err(DavError::Code(StatusCode::PRECONDITION_FAILED))
                    if headers.ret == Return::Representation =>
                {
                    return Ok(HttpResponse::new(StatusCode::PRECONDITION_FAILED)
                        .with_content_type("text/calendar; charset=utf-8")
                        .with_etag(event.etag())
                        .with_last_modified(
                            Rfc1123DateTime::new(i64::from(event.inner.modified)).to_string(),
                        )
                        .with_header("Preference-Applied", "return=representation")
                        .with_binary_body(event.inner.event.to_string()));
                }
                Err(e) => return Err(e),
            }

            // Validate quota
            let extra_bytes =
                (bytes.len() as u64).saturating_sub(u32::from(event.inner.size) as u64);
            if extra_bytes > 0 {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    extra_bytes,
                )
                .await?;
            }

            // Validate iCal
            if event.inner.event.uids().next().unwrap_or_default() != validate_ical(&ical)? {
                return Err(DavError::Condition(DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::NoUidConflict(resources.format_resource(resource).into()),
                )));
            }

            // Build node
            let mut new_event = event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;
            new_event.size = bytes.len() as u32;
            new_event.event = ical;

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let etag = new_event
                .update(access_token, event, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?
                .etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        } else if let Some((Some(parent), name)) = resources.map_parent(resource_name) {
            if !parent.is_container {
                return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
            }

            // Validate ACL
            if !access_token.is_member(account_id)
                && !self
                    .has_access_to_document(
                        access_token,
                        account_id,
                        Collection::Calendar,
                        parent.document_id,
                        Acl::AddItems,
                    )
                    .await
                    .caused_by(trc::location!())?
            {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }

            // Validate headers
            self.validate_headers(
                access_token,
                &headers,
                vec![ResourceState {
                    account_id,
                    collection: resource.collection,
                    document_id: Some(u32::MAX),
                    path: resource_name,
                    ..Default::default()
                }],
                Default::default(),
                DavMethod::PUT,
            )
            .await?;

            // Validate quota
            if !bytes.is_empty() {
                self.has_available_quota(
                    &self.get_resource_token(access_token, account_id).await?,
                    bytes.len() as u64,
                )
                .await?;
            }

            // Validate ical object
            assert_is_unique_uid(
                self,
                &resources,
                account_id,
                parent.document_id,
                validate_ical(&ical)?,
            )
            .await?;

            // Build node
            let event = CalendarEvent {
                names: vec![DavName {
                    name: name.to_string(),
                    parent_id: parent.document_id,
                }],
                event: ical,
                size: bytes.len() as u32,
                ..Default::default()
            };

            // Prepare write batch
            let mut batch = BatchBuilder::new();
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::CalendarEvent, 1)
                .await
                .caused_by(trc::location!())?;
            let etag = event
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?
                .etag();
            self.commit_batch(batch).await.caused_by(trc::location!())?;

            Ok(HttpResponse::new(StatusCode::CREATED).with_etag_opt(etag))
        } else {
            Err(DavError::Code(StatusCode::CONFLICT))?
        }
    }
}

fn validate_ical(ical: &ICalendar) -> crate::Result<&str> {
    // Validate UIDs
    let uids = ical.uids().collect::<HashSet<_>>();

    // Validate component types
    let mut types: [u8; 4] = [0; 4];
    for comp in &ical.components {
        match comp.component_type {
            ICalendarComponentType::VEvent => {
                types[0] += 1;
            }
            ICalendarComponentType::VTodo => {
                types[1] += 1;
            }
            ICalendarComponentType::VJournal => {
                types[2] += 1;
            }
            ICalendarComponentType::VFreebusy => {
                types[3] += 1;
            }
            _ => {}
        }
    }

    if uids.len() == 1 && types.iter().filter(|&&v| v == 0).count() == 3 {
        Ok(uids.iter().next().unwrap())
    } else {
        Err(DavError::Condition(DavErrorCondition::new(
            StatusCode::PRECONDITION_FAILED,
            CalCondition::ValidCalendarObjectResource,
        )))
    }
}
