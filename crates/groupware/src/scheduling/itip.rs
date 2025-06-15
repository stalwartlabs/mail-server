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
                values: vec![ICalendarValue::Text("Stalwart".to_string())],
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

pub(crate) fn itip_export_component(
    component: &ICalendarComponent,
    uid: &str,
    dt_stamp: &PartialDateTime,
    sequence: u32,
    export_as_organizer: Option<&ICalendarParticipationStatus>,
) -> ICalendarComponent {
    let mut comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(component.entries.len() + 1),
        component_ids: Default::default(),
    };

    comp.add_dtstamp(dt_stamp.clone());
    comp.add_sequence(sequence);
    comp.add_uid(uid);

    for entry in &component.entries {
        match &entry.name {
            ICalendarProperty::Organizer | ICalendarProperty::Attendee => {
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
                            has_partstat =
                                has_partstat || matches!(entry, ICalendarParameter::Partstat(_));
                            new_entry.params.push(entry.clone())
                        }
                    }
                }

                if !has_partstat && entry.name == ICalendarProperty::Attendee {
                    if let Some(partstat) = export_as_organizer {
                        new_entry
                            .params
                            .push(ICalendarParameter::Partstat(partstat.clone()));
                    }
                }

                comp.entries.push(new_entry);
            }
            ICalendarProperty::RequestStatus
            | ICalendarProperty::Dtstamp
            | ICalendarProperty::Sequence
            | ICalendarProperty::Uid => {}
            _ => {
                if export_as_organizer.is_some()
                    || matches!(entry.name, ICalendarProperty::RecurrenceId)
                {
                    comp.entries.push(entry.clone());
                }
            }
        }
    }

    comp
}

pub fn itip_remove_info(ical: &mut ICalendar) {
    let todo = "call after insert or update";
    for comp in ical.components.iter_mut() {
        if comp.component_type.is_scheduling_object() {
            // Remove scheduling info from non-updated components
            for entry in comp.entries.iter_mut() {
                if matches!(
                    entry.name,
                    ICalendarProperty::Organizer | ICalendarProperty::Attendee
                ) {
                    entry.params.retain(|param| {
                        !matches!(
                            param,
                            ICalendarParameter::Rsvp(true)
                                | ICalendarParameter::ScheduleForceSend(_)
                        )
                    });
                }
            }
        }
    }
}
