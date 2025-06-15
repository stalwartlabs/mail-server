/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParticipationStatus, ICalendarProperty, ICalendarValue,
    },
    scheduling::ItipError,
};

pub(crate) fn itip_build_envelope(method: ICalendarMethod) -> ICalendarComponent {
    let todo = "fix prodid";
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
                values: vec![ICalendarValue::Text(
                    "-//Stalwart Labs LLC//Stalwart Server//EN".to_string(),
                )],
            },
            ICalendarEntry {
                name: ICalendarProperty::Method,
                params: vec![],
                values: vec![ICalendarValue::Method(method)],
            },
        ],
        component_ids: Default::default(),
    }
}

pub(crate) enum ItipExportAs<'x> {
    Organizer(&'x ICalendarParticipationStatus),
    Attendee(Vec<u16>),
}

pub(crate) fn itip_export_component(
    component: &ICalendarComponent,
    uid: &str,
    dt_stamp: &PartialDateTime,
    sequence: i64,
    export_as: ItipExportAs<'_>,
) -> ICalendarComponent {
    let mut comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(component.entries.len() + 1),
        component_ids: Default::default(),
    };

    comp.add_dtstamp(dt_stamp.clone());
    comp.add_sequence(sequence);
    comp.add_uid(uid);

    for (entry_id, entry) in component.entries.iter().enumerate() {
        match &entry.name {
            ICalendarProperty::Organizer | ICalendarProperty::Attendee => match &export_as {
                ItipExportAs::Organizer(partstat) => {
                    let mut new_entry = ICalendarEntry {
                        name: entry.name.clone(),
                        params: Vec::with_capacity(entry.params.len()),
                        values: entry.values.clone(),
                    };
                    let mut has_partstat = false;

                    for entry in &entry.params {
                        match entry {
                            ICalendarParameter::ScheduleStatus(_)
                            | ICalendarParameter::ScheduleAgent(_)
                            | ICalendarParameter::ScheduleForceSend(_) => {}
                            _ => {
                                has_partstat = has_partstat
                                    || matches!(entry, ICalendarParameter::Partstat(_));
                                new_entry.params.push(entry.clone())
                            }
                        }
                    }

                    if !has_partstat && entry.name == ICalendarProperty::Attendee {
                        new_entry
                            .params
                            .push(ICalendarParameter::Partstat((*partstat).clone()));
                    }

                    comp.entries.push(new_entry);
                }
                ItipExportAs::Attendee(attendee_entry_ids)
                    if attendee_entry_ids.contains(&(entry_id as u16))
                        || entry.name == ICalendarProperty::Organizer =>
                {
                    comp.entries.push(ICalendarEntry {
                        name: entry.name.clone(),
                        params: entry
                            .params
                            .iter()
                            .filter(|param| {
                                !matches!(
                                    param,
                                    ICalendarParameter::ScheduleStatus(_)
                                        | ICalendarParameter::ScheduleAgent(_)
                                        | ICalendarParameter::ScheduleForceSend(_)
                                )
                            })
                            .cloned()
                            .collect(),
                        values: entry.values.clone(),
                    });
                }
                _ => {}
            },
            ICalendarProperty::RequestStatus
            | ICalendarProperty::Dtstamp
            | ICalendarProperty::Sequence
            | ICalendarProperty::Uid => {}
            _ => {
                if matches!(export_as, ItipExportAs::Organizer(_))
                    || matches!(entry.name, ICalendarProperty::RecurrenceId)
                {
                    comp.entries.push(entry.clone());
                }
            }
        }
    }

    if matches!(export_as, ItipExportAs::Attendee(_)) {
        comp.entries.push(ICalendarEntry {
            name: ICalendarProperty::RequestStatus,
            params: vec![],
            values: vec![
                ICalendarValue::Text("2.0".to_string()),
                ICalendarValue::Text("Success".to_string()),
            ],
        });
    }

    comp
}

pub(crate) fn itip_finalize(ical: &mut ICalendar, scheduling_object_ids: &[u16]) {
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            // Remove scheduling info from non-updated components
            for entry in comp.entries.iter_mut() {
                if matches!(
                    entry.name,
                    ICalendarProperty::Organizer | ICalendarProperty::Attendee
                ) {
                    entry
                        .params
                        .retain(|param| !matches!(param, ICalendarParameter::ScheduleForceSend(_)));
                }
            }
        }
    }

    for comp_id in scheduling_object_ids {
        let comp = &mut ical.components[*comp_id as usize];
        let mut found_sequence = false;
        for entry in &mut comp.entries {
            if entry.name == ICalendarProperty::Sequence {
                if let Some(ICalendarValue::Integer(seq)) = entry.values.first_mut() {
                    *seq += 1;
                } else {
                    entry.values = vec![ICalendarValue::Integer(1)];
                }
                found_sequence = true;
                break;
            }
        }

        if !found_sequence {
            comp.add_sequence(1);
        }
    }
}

pub fn itip_import_message(ical: &mut ICalendar) -> Result<(), ItipError> {
    let mut expect_object_type = None;
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            match expect_object_type {
                Some(expected) if expected != &comp.component_type => {
                    return Err(ItipError::MultipleObjectTypes);
                }
                None => {
                    expect_object_type = Some(&comp.component_type);
                }
                _ => {}
            }
        } else if comp.component_type == ICalendarComponentType::VCalendar {
            comp.entries
                .retain(|entry| !matches!(entry.name, ICalendarProperty::Method));
        }
    }

    Ok(())
}

pub(crate) fn itip_add_tz(message: &mut ICalendar, ical: &ICalendar) {
    let mut has_timezones = false;

    if message.components.iter().any(|c| {
        has_timezones = has_timezones || c.component_type == ICalendarComponentType::VTimezone;

        !has_timezones
            && c.entries.iter().any(|e| {
                e.params
                    .iter()
                    .any(|p| matches!(p, ICalendarParameter::Tzid(_)))
            })
    }) && !has_timezones
    {
        message.copy_timezones(ical);
    }
}
