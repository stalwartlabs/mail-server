/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use super::query::CalendarQueryHandler;
use crate::{DavError, calendar::query::is_resource_in_time_range, common::uri::DavUriResource};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ArchivedICalendarComponentType, ArchivedICalendarEntry, ArchivedICalendarParameter,
        ArchivedICalendarProperty, ArchivedICalendarStatus, ArchivedICalendarValue, ICalendar,
        ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarFreeBusyType,
        ICalendarParameter, ICalendarPeriod, ICalendarProperty, ICalendarTransparency,
        ICalendarValue,
    },
};
use common::{PROD_ID, Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders,
    schema::{property::TimeRange, request::FreeBusyQuery},
};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use http_proto::HttpResponse;
use hyper::StatusCode;
use jmap_proto::types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use store::{
    ahash::AHashMap,
    write::{now, serialize::rkyv_deserialize},
};
use trc::AddContext;

pub(crate) trait CalendarFreebusyRequestHandler: Sync + Send {
    fn handle_calendar_freebusy_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: FreeBusyQuery,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarFreebusyRequestHandler for Server {
    async fn handle_calendar_freebusy_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: FreeBusyQuery,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let resource = resources
            .by_path(
                resource_
                    .resource
                    .ok_or(DavError::Code(StatusCode::METHOD_NOT_ALLOWED))?,
            )
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.is_container() {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }
        let default_tz = resource.resource.timezone().unwrap_or(Tz::UTC);

        // Obtain shared ids
        let shared_ids = if !access_token.is_member(account_id) {
            resources
                .shared_containers(access_token, [Acl::ReadItems, Acl::ReadFreeBusy], false)
                .into()
        } else {
            None
        };

        // Build FreeBusy component
        let mut entries = Vec::with_capacity(6);
        if let Some(range) = request.range {
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtstart,
                params: vec![],
                values: vec![ICalendarValue::PartialDateTime(Box::new(
                    PartialDateTime::from_utc_timestamp(range.start),
                ))],
            });
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtend,
                params: vec![],
                values: vec![ICalendarValue::PartialDateTime(Box::new(
                    PartialDateTime::from_utc_timestamp(range.end),
                ))],
            });
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Dtstamp,
                params: vec![],
                values: vec![ICalendarValue::PartialDateTime(Box::new(
                    PartialDateTime::from_utc_timestamp(now() as i64),
                ))],
            });

            let document_ids = resources
                .children(resource.document_id())
                .filter(|resource| {
                    shared_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(resource.document_id()))
                        && is_resource_in_time_range(resource.resource, &range)
                })
                .map(|resource| resource.document_id())
                .collect::<Vec<_>>();

            let mut fb_entries: AHashMap<ICalendarFreeBusyType, Vec<(i64, i64)>> =
                AHashMap::with_capacity(document_ids.len());

            for document_id in document_ids {
                let archive = if let Some(archive) = self
                    .get_archive(account_id, Collection::CalendarEvent, document_id)
                    .await
                    .caused_by(trc::location!())?
                {
                    archive
                } else {
                    continue;
                };
                let event = archive
                    .unarchive::<CalendarEvent>()
                    .caused_by(trc::location!())?;

                /*
                   Only VEVENT components without a TRANSP property or with the TRANSP
                   property set to OPAQUE, and VFREEBUSY components SHOULD be considered
                   in generating the free busy time information.
                */
                let mut components = event
                    .data
                    .event
                    .components
                    .iter()
                    .enumerate()
                    .filter(|(_, comp)| {
                        (matches!(comp.component_type, ArchivedICalendarComponentType::VEvent)
                            && comp
                                .transparency()
                                .is_none_or(|t| t == &ICalendarTransparency::Opaque))
                            || matches!(
                                comp.component_type,
                                ArchivedICalendarComponentType::VFreebusy
                            )
                    })
                    .peekable();

                if components.peek().is_none() {
                    continue;
                }

                let events =
                    CalendarQueryHandler::new(event, Some(range), default_tz).into_expanded_times();

                if events.is_empty() {
                    continue;
                }

                for (component_id, component) in components {
                    let component_id = component_id as u16;
                    match component.component_type {
                        ArchivedICalendarComponentType::VEvent => {
                            let fbtype = match component.status() {
                                Some(ArchivedICalendarStatus::Cancelled) => continue,
                                Some(ArchivedICalendarStatus::Tentative) => {
                                    ICalendarFreeBusyType::BusyTentative
                                }
                                Some(ArchivedICalendarStatus::Other(v)) => {
                                    ICalendarFreeBusyType::Other(v.as_str().to_string())
                                }
                                _ => ICalendarFreeBusyType::Busy,
                            };

                            let mut events_in_range = Vec::new();
                            for event in &events {
                                if event.comp_id == component_id
                                    && range.is_in_range(false, event.start, event.end)
                                {
                                    events_in_range.push((event.start, event.end));
                                }
                            }

                            if !events_in_range.is_empty() {
                                fb_entries
                                    .entry(fbtype)
                                    .or_default()
                                    .extend(events_in_range);
                            }
                        }
                        ArchivedICalendarComponentType::VFreebusy => {
                            for entry in component.entries.iter() {
                                if matches!(entry.name, ArchivedICalendarProperty::Freebusy) {
                                    let mut fb_in_range =
                                        freebusy_in_range_utc(entry, &range, default_tz).peekable();
                                    if fb_in_range.peek().is_some() {
                                        let fb_type = entry
                                            .params
                                            .iter()
                                            .find_map(|param| {
                                                if let ArchivedICalendarParameter::Fbtype(param) =
                                                    param
                                                {
                                                    rkyv_deserialize(param).ok()
                                                } else {
                                                    None
                                                }
                                            })
                                            .unwrap_or(ICalendarFreeBusyType::Busy);

                                        fb_entries.entry(fb_type).or_default().extend(fb_in_range);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            for (fbtype, events_in_range) in fb_entries {
                entries.push(ICalendarEntry {
                    name: ICalendarProperty::Freebusy,
                    params: vec![ICalendarParameter::Fbtype(fbtype)],
                    values: merge_intervals(events_in_range),
                });
            }
        }

        // Build ICalendar
        let ical = ICalendar {
            components: vec![
                ICalendarComponent {
                    component_type: ICalendarComponentType::VCalendar,
                    entries: vec![
                        ICalendarEntry {
                            name: ICalendarProperty::Version,
                            params: vec![],
                            values: vec![ICalendarValue::Text("2.0".to_string())],
                        },
                        ICalendarEntry {
                            name: ICalendarProperty::Prodid,
                            params: vec![],
                            values: vec![ICalendarValue::Text(PROD_ID.to_string())],
                        },
                    ],
                    component_ids: vec![1],
                },
                ICalendarComponent {
                    component_type: ICalendarComponentType::VFreebusy,
                    entries,
                    component_ids: vec![],
                },
            ],
        }
        .to_string();

        Ok(HttpResponse::new(StatusCode::OK)
            .with_content_type("text/calendar; charset=utf-8")
            .with_text_body(ical))
    }
}

fn merge_intervals(mut intervals: Vec<(i64, i64)>) -> Vec<ICalendarValue> {
    if intervals.len() > 1 {
        intervals.sort_by(|a, b| a.0.cmp(&b.0));

        let mut unique_intervals = Vec::new();
        let mut start_time = intervals[0].0;
        let mut end_time = intervals[0].1;

        for &(curr_start, curr_end) in intervals.iter().skip(1) {
            if curr_start <= end_time {
                end_time = end_time.max(curr_end);
            } else {
                unique_intervals.push(build_ical_value(start_time, end_time));
                start_time = curr_start;
                end_time = curr_end;
            }
        }

        unique_intervals.push(build_ical_value(start_time, end_time));
        unique_intervals
    } else {
        intervals
            .into_iter()
            .map(|(start, end)| build_ical_value(start, end))
            .collect()
    }
}

fn build_ical_value(from: i64, to: i64) -> ICalendarValue {
    ICalendarValue::Period(ICalendarPeriod::Range {
        start: PartialDateTime::from_utc_timestamp(from),
        end: PartialDateTime::from_utc_timestamp(to),
    })
}

pub(crate) fn freebusy_in_range(
    entry: &ArchivedICalendarEntry,
    range: &TimeRange,
    default_tz: Tz,
) -> impl Iterator<Item = ICalendarValue> {
    let tz = entry
        .tz_id()
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(default_tz);

    entry.values.iter().filter_map(move |value| {
        if let ArchivedICalendarValue::Period(period) = &value {
            period.time_range(tz).and_then(|(start, end)| {
                let start = start.timestamp();
                let end = end.timestamp();
                if range.is_in_range(false, start, end) {
                    rkyv_deserialize(value).ok()
                } else {
                    None
                }
            })
        } else {
            None
        }
    })
}

fn freebusy_in_range_utc(
    entry: &ArchivedICalendarEntry,
    range: &TimeRange,
    default_tz: Tz,
) -> impl Iterator<Item = (i64, i64)> {
    let tz = entry
        .tz_id()
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(default_tz);

    entry.values.iter().filter_map(move |value| {
        if let ArchivedICalendarValue::Period(period) = &value {
            period.time_range(tz).and_then(|(start, end)| {
                let start = start.timestamp();
                let end = end.timestamp();
                if range.is_in_range(false, start, end) {
                    Some((start, end))
                } else {
                    None
                }
            })
        } else {
            None
        }
    })
}
