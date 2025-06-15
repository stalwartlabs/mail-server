/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    icalendar::{
        ICalendar, ICalendarParameter, ICalendarProperty, ICalendarScheduleAgentValue,
        ICalendarValue, Uri,
    },
    scheduling::{
        Attendee, Email, InstanceId, ItipEntry, ItipEntryValue, ItipError, ItipSnapshot,
        ItipSnapshots, Organizer, RecurrenceId, UnresolvedDateTime,
    },
};
use ahash::AHashMap;

pub(crate) fn itip_snapshot<'x>(
    ical: &'x ICalendar,
    account_emails: &'x [&'x str],
    force_add_client_scheduling: bool,
) -> Result<ItipSnapshots<'x>, ItipError> {
    let mut organizer: Option<Organizer<'x>> = None;
    let mut uid: Option<&'x str> = None;
    let mut sequence: Option<i64> = None;
    let mut components = AHashMap::new();
    let mut expect_object_type = None;
    let mut has_local_emails = false;

    for (comp_id, comp) in ical.components.iter().enumerate() {
        if comp.component_type.is_scheduling_object()
            && comp
                .entries
                .iter()
                .any(|e| matches!(e.name, ICalendarProperty::Organizer))
        {
            match expect_object_type {
                Some(expected) if expected != &comp.component_type => {
                    return Err(ItipError::MultipleObjectTypes);
                }
                None => {
                    expect_object_type = Some(&comp.component_type);
                }
                _ => {}
            }

            let mut sched_comp = ItipSnapshot {
                comp_id: comp_id as u16,
                ..Default::default()
            };
            let mut instance_id = InstanceId::Main;

            for (entry_id, entry) in comp.entries.iter().enumerate() {
                match &entry.name {
                    ICalendarProperty::Organizer => {
                        if let Some(email) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .and_then(|v| Email::new(v, account_emails))
                        {
                            let mut part = Organizer {
                                entry_id: entry_id as u16,
                                email,
                                is_server_scheduling: true,
                                force_send: None,
                            };
                            has_local_emails |= part.email.is_local;

                            for param in &entry.params {
                                match param {
                                    ICalendarParameter::ScheduleAgent(agent) => {
                                        part.is_server_scheduling =
                                            agent == &ICalendarScheduleAgentValue::Server;
                                    }
                                    ICalendarParameter::ScheduleForceSend(force_send) => {
                                        part.force_send = Some(force_send);
                                    }
                                    _ => {}
                                }
                            }

                            if !part.is_server_scheduling && !force_add_client_scheduling {
                                return Err(ItipError::OtherSchedulingAgent);
                            }

                            match organizer {
                                Some(existing_organizer)
                                    if existing_organizer.email.email != part.email.email =>
                                {
                                    return Err(ItipError::MultipleOrganizer);
                                }
                                None => {
                                    organizer = Some(part);
                                }
                                _ => {}
                            }
                        }
                    }
                    ICalendarProperty::Attendee => {
                        if let Some(email) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .and_then(|v| Email::new(v, account_emails))
                        {
                            let mut part = Attendee {
                                entry_id: entry_id as u16,
                                email,
                                rsvp: None,
                                is_server_scheduling: true,
                                force_send: None,
                                part_stat: None,
                                delegated_from: vec![],
                                delegated_to: vec![],
                                cu_type: None,
                                role: None,
                                sent_by: None,
                            };

                            for param in &entry.params {
                                match param {
                                    ICalendarParameter::ScheduleAgent(agent) => {
                                        part.is_server_scheduling =
                                            agent == &ICalendarScheduleAgentValue::Server;
                                    }
                                    ICalendarParameter::Rsvp(rsvp) => {
                                        part.rsvp = Some(*rsvp);
                                    }
                                    ICalendarParameter::ScheduleForceSend(force_send) => {
                                        part.force_send = Some(force_send);
                                    }
                                    ICalendarParameter::Partstat(value) => {
                                        part.part_stat = Some(value);
                                    }
                                    ICalendarParameter::Cutype(value) => {
                                        part.cu_type = Some(value);
                                    }
                                    ICalendarParameter::DelegatedFrom(value) => {
                                        part.delegated_from = value
                                            .iter()
                                            .filter_map(|uri| Email::from_uri(uri, account_emails))
                                            .collect();
                                    }
                                    ICalendarParameter::DelegatedTo(value) => {
                                        part.delegated_to = value
                                            .iter()
                                            .filter_map(|uri| Email::from_uri(uri, account_emails))
                                            .collect();
                                    }
                                    ICalendarParameter::Role(value) => {
                                        part.role = Some(value);
                                    }
                                    ICalendarParameter::SentBy(value) => {
                                        part.sent_by = Email::from_uri(value, account_emails);
                                    }
                                    _ => {}
                                }
                            }

                            has_local_emails |= part.email.is_local
                                && (force_add_client_scheduling || part.is_server_scheduling);

                            sched_comp.attendees.insert(part);
                        }
                    }
                    ICalendarProperty::Uid => {
                        if let Some(uid_) = entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .map(|v| v.trim())
                            .filter(|v| !v.is_empty())
                        {
                            match uid {
                                Some(existing_uid) if existing_uid != uid_ => {
                                    return Err(ItipError::MultipleUid);
                                }
                                None => {
                                    uid = Some(uid_);
                                }
                                _ => {}
                            }
                        }
                    }
                    ICalendarProperty::Sequence => {
                        if let Some(sequence_) = entry.values.first().and_then(|v| v.as_integer()) {
                            match sequence {
                                Some(existing_sequence) if existing_sequence != sequence_ => {
                                    return Err(ItipError::MultipleSequence);
                                }
                                None => {
                                    sequence = Some(sequence_);
                                }
                                _ => {}
                            }
                        }
                    }
                    ICalendarProperty::RecurrenceId => {
                        if let Some(date) =
                            entry.values.first().and_then(|v| v.as_partial_date_time())
                        {
                            let mut recurrence_id = RecurrenceId {
                                entry_id: entry_id as u16,
                                date: UnresolvedDateTime { date, tz_id: None },
                                this_and_future: false,
                            };
                            for param in &entry.params {
                                match param {
                                    ICalendarParameter::Tzid(id) => {
                                        recurrence_id.date.tz_id = Some(id.as_str());
                                    }
                                    ICalendarParameter::Range => {
                                        recurrence_id.this_and_future = true;
                                    }
                                    _ => (),
                                }
                            }

                            instance_id = InstanceId::Recurrence(recurrence_id);
                        }
                    }
                    ICalendarProperty::RequestStatus => {
                        if let Some(value) = entry.values.first().and_then(|v| v.as_text()) {
                            sched_comp.request_status.push(value);
                        }
                    }
                    ICalendarProperty::Dtstamp => {
                        sched_comp.dtstamp =
                            entry.values.first().and_then(|v| v.as_partial_date_time());
                    }
                    ICalendarProperty::Dtstart
                    | ICalendarProperty::Dtend
                    | ICalendarProperty::Duration
                    | ICalendarProperty::Due
                    | ICalendarProperty::Rrule
                    | ICalendarProperty::Rdate
                    | ICalendarProperty::Exdate
                    | ICalendarProperty::Status
                    | ICalendarProperty::Location
                    | ICalendarProperty::Summary
                    | ICalendarProperty::Description
                    | ICalendarProperty::Priority => {
                        let tz_id = entry.tz_id();
                        for value in &entry.values {
                            let value = match value {
                                ICalendarValue::Uri(Uri::Location(v)) => {
                                    ItipEntryValue::Text(v.as_str())
                                }
                                ICalendarValue::PartialDateTime(partial_date_time) => {
                                    ItipEntryValue::DateTime(UnresolvedDateTime {
                                        date: partial_date_time,
                                        tz_id,
                                    })
                                }
                                ICalendarValue::Duration(v) => ItipEntryValue::Duration(v),
                                ICalendarValue::RecurrenceRule(v) => ItipEntryValue::RRule(v),
                                ICalendarValue::Period(v) => ItipEntryValue::Period(v),
                                ICalendarValue::Integer(v) => ItipEntryValue::Integer(*v),
                                ICalendarValue::Text(v) => ItipEntryValue::Text(v.as_str()),
                                ICalendarValue::Status(v) => ItipEntryValue::Status(v),
                                _ => continue,
                            };
                            sched_comp.entries.insert(ItipEntry {
                                name: &entry.name,
                                value,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if components.insert(instance_id, sched_comp).is_some() {
                return Err(ItipError::MultipleObjectInstances);
            }
        }
    }

    if !components.is_empty() && has_local_emails {
        Ok(ItipSnapshots {
            organizer: organizer.ok_or(ItipError::NoSchedulingInfo)?,
            uid: uid.ok_or(ItipError::MissingUid)?,
            sequence,
            components,
        })
    } else if !has_local_emails {
        Err(ItipError::NotOrganizerNorAttendee)
    } else {
        Err(ItipError::NoSchedulingInfo)
    }
}
