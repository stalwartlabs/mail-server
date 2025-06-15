/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use crate::{
    DavError, DavMethod, PropStatBuilder,
    common::{
        ETag, ExtractETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use calcard::common::timezone::Tz;
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        Namespace,
        property::{CalDavProperty, DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate},
        response::{BaseCondition, CalCondition, MultiStatus, Response},
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{Calendar, CalendarEvent, Timezone},
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::write::BatchBuilder;
use trc::AddContext;

pub(crate) trait CalendarPropPatchRequestHandler: Sync + Send {
    fn handle_calendar_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_calendar_properties(
        &self,
        account_id: u32,
        calendar: &mut Calendar,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool;

    fn apply_event_properties(
        &self,
        event: &mut CalendarEvent,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool;
}

impl CalendarPropPatchRequestHandler for Server {
    async fn handle_calendar_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let uri = headers.uri;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.by_path(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = resource.document_id();
        let collection = if resource.is_container() {
            Collection::Calendar
        } else {
            Collection::CalendarEvent
        };

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Verify ACL
        if !access_token.is_member(account_id) {
            let (acl, document_id) = if resource.is_container() {
                (Acl::Modify, resource.document_id())
            } else {
                (Acl::ModifyItems, resource.parent_id().unwrap())
            };

            if !resources.has_access_to_container(access_token, document_id, acl) {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Fetch archive
        let archive = self
            .get_archive(account_id, collection, document_id)
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection,
                document_id: document_id.into(),
                etag: archive.etag().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        let is_success;
        let mut batch = BatchBuilder::new();
        let mut items = PropStatBuilder::default();

        let etag = if resource.is_container() {
            // Deserialize
            let calendar = archive
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;
            let mut new_calendar = archive
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;

            // Remove properties
            if !request.set_first && !request.remove.is_empty() {
                remove_calendar_properties(
                    account_id,
                    &mut new_calendar,
                    std::mem::take(&mut request.remove),
                    &mut items,
                );
            }

            // Set properties
            is_success = self.apply_calendar_properties(
                account_id,
                &mut new_calendar,
                true,
                request.set,
                &mut items,
            );

            // Remove properties
            if is_success && !request.remove.is_empty() {
                remove_calendar_properties(
                    account_id,
                    &mut new_calendar,
                    request.remove,
                    &mut items,
                );
            }

            if is_success {
                new_calendar
                    .update(access_token, calendar, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?
                    .etag()
            } else {
                calendar.etag().into()
            }
        } else {
            // Deserialize
            let event = archive
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_event = archive
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Remove properties
            if !request.set_first && !request.remove.is_empty() {
                remove_event_properties(
                    &mut new_event,
                    std::mem::take(&mut request.remove),
                    &mut items,
                );
            }

            // Set properties
            is_success = self.apply_event_properties(&mut new_event, true, request.set, &mut items);

            // Remove properties
            if is_success && !request.remove.is_empty() {
                remove_event_properties(&mut new_event, request.remove, &mut items);
            }

            if is_success {
                new_event
                    .update(access_token, event, account_id, document_id, &mut batch)
                    .caused_by(trc::location!())?
                    .etag()
            } else {
                event.etag().into()
            }
        };

        if is_success {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items.build())])
                        .with_namespace(Namespace::CalDav)
                        .to_string(),
                )
                .with_etag_opt(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag_opt(etag))
        }
    }

    fn apply_calendar_properties(
        &self,
        account_id: u32,
        calendar: &mut Calendar,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        calendar.preferences_mut(account_id).name = name;
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (
                    DavProperty::CalDav(CalDavProperty::CalendarDescription),
                    DavValue::String(name),
                ) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        calendar.preferences_mut(account_id).description = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );

                        has_errors = true;
                    }
                }
                (
                    DavProperty::CalDav(CalDavProperty::CalendarTimezone),
                    DavValue::ICalendar(ical),
                ) => {
                    if ical.size() > self.core.groupware.max_ical_size {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    } else if !ical.is_timezone() {
                        items.insert_precondition_failed_with_description(
                            property.property,
                            StatusCode::PRECONDITION_FAILED,
                            CalCondition::ValidCalendarData,
                            "Invalid calendar timezone",
                        );
                        has_errors = true;
                    } else {
                        calendar.preferences_mut(account_id).time_zone = Timezone::Custom(ical);
                        items.insert_ok(property.property);
                    }
                }
                (DavProperty::CalDav(CalDavProperty::TimezoneId), DavValue::String(tz_id)) => {
                    if let Ok(tz) = Tz::from_str(&tz_id) {
                        calendar.preferences_mut(account_id).time_zone = Timezone::IANA(tz.as_id());
                        items.insert_ok(property.property);
                    } else {
                        items.insert_precondition_failed_with_description(
                            property.property,
                            StatusCode::PRECONDITION_FAILED,
                            CalCondition::ValidTimezone,
                            "Invalid timezone ID",
                        );
                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    calendar.created = dt;
                    items.insert_ok(property.property);
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) => {
                    if !types
                        .0
                        .iter()
                        .all(|rt| matches!(rt, ResourceType::Collection | ResourceType::Calendar))
                    {
                        items.insert_precondition_failed(
                            property.property,
                            StatusCode::FORBIDDEN,
                            BaseCondition::ValidResourceType,
                        );
                        has_errors = true;
                    } else {
                        items.insert_ok(property.property);
                    }
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.groupware.dead_property_size.is_some() =>
                {
                    if is_update {
                        calendar.dead_properties.remove_element(dead);
                    }

                    if calendar.dead_properties.size() + values.size() + dead.size()
                        < self.core.groupware.dead_property_size.unwrap()
                    {
                        calendar.dead_properties.add_element(dead.clone(), values.0);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );

                        has_errors = true;
                    }
                }
                (_, DavValue::Null | DavValue::Components(_)) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                    has_errors = true;
                }
            }
        }

        !has_errors
    }

    fn apply_event_properties(
        &self,
        event: &mut CalendarEvent,
        is_update: bool,
        properties: Vec<DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) -> bool {
        let mut has_errors = false;

        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        event.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    event.created = dt;
                    items.insert_ok(property.property);
                }
                (DavProperty::DeadProperty(dead), DavValue::DeadProperty(values))
                    if self.core.groupware.dead_property_size.is_some() =>
                {
                    if is_update {
                        event.dead_properties.remove_element(dead);
                    }

                    if event.dead_properties.size() + values.size() + dead.size()
                        < self.core.groupware.dead_property_size.unwrap()
                    {
                        event.dead_properties.add_element(dead.clone(), values.0);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                        has_errors = true;
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                    has_errors = true;
                }
            }
        }

        !has_errors
    }
}

fn remove_event_properties(
    event: &mut CalendarEvent,
    properties: Vec<DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                event.display_name = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::DeadProperty(dead) => {
                event.dead_properties.remove_element(dead);
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}

fn remove_calendar_properties(
    account_id: u32,
    calendar: &mut Calendar,
    properties: Vec<DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::CalDav(CalDavProperty::CalendarDescription) => {
                calendar.preferences_mut(account_id).description = None;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::CalDav(CalDavProperty::CalendarTimezone)
            | DavProperty::CalDav(CalDavProperty::TimezoneId) => {
                calendar.preferences_mut(account_id).time_zone = Timezone::Default;
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            DavProperty::DeadProperty(dead) => {
                calendar.dead_properties.remove_element(dead);
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}
