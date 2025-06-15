/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarMethod,
        ICalendarParticipationStatus, ICalendarProperty,
    },
    scheduling::{
        event_cancel::cancel_component,
        itip::{itip_build_envelope, itip_export_component},
        InstanceId, ItipError, ItipMessage, ItipSnapshots, SchedulingInfo,
    },
};
use ahash::AHashSet;

pub(crate) fn organizer_handle_update(
    old_ical: &ICalendar,
    new_ical: &ICalendar,
    old_itip: ItipSnapshots<'_>,
    new_itip: ItipSnapshots<'_>,
    info: &mut SchedulingInfo,
) -> Result<ItipMessage, ItipError> {
    let mut added_instances = Vec::new();
    let mut deleted_instances = Vec::new();
    let mut updated_instances = Vec::new();
    let mut is_full_update = false;
    let mut increment_sequence = false;

    for (instance_id, instance) in &new_itip.components {
        if let Some(old_instance) = old_itip.components.get(instance_id) {
            let changed_entries = instance.entries != old_instance.entries;
            let changed_attendees = instance.attendees != old_instance.attendees;

            if changed_entries || changed_attendees {
                increment_sequence = increment_sequence
                    || changed_attendees
                    || instance
                        .entries
                        .symmetric_difference(&old_instance.entries)
                        .any(|entry| {
                            !matches!(
                                entry.name,
                                ICalendarProperty::Summary
                                    | ICalendarProperty::Description
                                    | ICalendarProperty::Priority
                            )
                        });

                if instance_id == &InstanceId::Main {
                    is_full_update = true;
                    break;
                } else {
                    updated_instances.push((instance_id, instance));
                }
            }
        } else if instance_id != &InstanceId::Main {
            added_instances.push((instance_id, instance));
            increment_sequence = true;
        } else {
            return Err(ItipError::ChangeNotAllowed);
        }
    }

    if !is_full_update {
        for (instance_id, old_instance) in &old_itip.components {
            if !new_itip.components.contains_key(instance_id) {
                if instance_id != &InstanceId::Main {
                    deleted_instances.push((instance_id, old_instance));
                    increment_sequence = true;
                } else {
                    return Err(ItipError::ChangeNotAllowed);
                }
            }
        }
    }

    let sequence = if increment_sequence {
        info.sequence + 1
    } else {
        info.sequence
    };

    let (method, instances) = match (
        !added_instances.is_empty(),
        !deleted_instances.is_empty(),
        !updated_instances.is_empty(),
        is_full_update,
    ) {
        (true, false, false, false) => {
            // Send ADD message
            (ICalendarMethod::Add, added_instances)
        }
        (false, true, false, false) => {
            // Send CANCEL message
            (ICalendarMethod::Cancel, deleted_instances)
        }
        (false, false, true, false) => {
            // Send REQUEST message for changed instances
            (ICalendarMethod::Request, updated_instances)
        }
        (_, _, _, true) => {
            // Send full REQUEST message
            return organizer_request_full(new_ical, new_itip, sequence, false).inspect(|_| {
                info.sequence = sequence;
            });
        }
        _ => return Err(ItipError::NothingToSend),
    };

    // Prepare iTIP message
    let (ical, itip, is_cancel) = if matches!(method, ICalendarMethod::Cancel) {
        (old_ical, &old_itip, true)
    } else {
        (new_ical, &new_itip, false)
    };
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: vec![ICalendarComponent::default(); ical.components.len()],
    };
    message.components[0] = itip_build_envelope(method);

    let mut recipients = AHashSet::new();
    let mut copy_components = AHashSet::new();
    let mut scheduling_component_ids = Vec::with_capacity(ical.components.len());

    for (instance_id, comp) in instances {
        // Prepare component for iTIP
        let orig_component = &ical.components[comp.comp_id as usize];
        let component = if !is_cancel {
            // Add attendees
            for attendee in &comp.attendees {
                if attendee.send_scheduling_messages() {
                    recipients.insert(attendee.email.email.as_str());
                }
            }

            // Export component with updated sequence and participation status
            itip_export_component(
                orig_component,
                itip.uid,
                &dt_stamp,
                sequence,
                Some(&ICalendarParticipationStatus::NeedsAction),
            )
        } else if let Some(mut cancel_comp) = cancel_component(
            ical,
            itip,
            comp,
            sequence,
            dt_stamp.clone(),
            &mut recipients,
        ) {
            if let InstanceId::Recurrence(recurrence_id) = instance_id {
                cancel_comp
                    .entries
                    .push(orig_component.entries[recurrence_id.entry_id as usize].clone());
            }
            cancel_comp
        } else {
            continue; // Skip if no component was created
        };

        // Add component to message
        scheduling_component_ids.push(comp.comp_id);
        message.components[comp.comp_id as usize] = component;
        message.components[0].component_ids.push(comp.comp_id);
    }

    // Copy timezones and alarms
    for (comp_id, comp) in ical.components.iter().enumerate() {
        if !is_cancel && matches!(comp.component_type, ICalendarComponentType::VTimezone) {
            copy_components.extend(comp.component_ids.iter().copied());
        } else if !copy_components.contains(&(comp_id as u16)) {
            continue;
        }
        message.components.push(comp.clone());
        message.components[0].component_ids.push(comp_id as u16);
    }

    if !recipients.is_empty() {
        if increment_sequence {
            info.sequence = sequence;
        }

        Ok(ItipMessage {
            method: ICalendarMethod::Request,
            from: itip.organizer.email.email.clone(),
            to: recipients.into_iter().map(|e| e.to_string()).collect(),
            changed_properties: vec![],
            message,
        })
    } else {
        Err(ItipError::NothingToSend)
    }
}

pub(crate) fn organizer_request_full(
    ical: &ICalendar,
    itip: ItipSnapshots<'_>,
    sequence: u32,
    include_alarms: bool,
) -> Result<ItipMessage, ItipError> {
    // Prepare iTIP message
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: vec![ICalendarComponent::default(); ical.components.len()],
    };
    message.components[0] = itip_build_envelope(ICalendarMethod::Request);

    let mut recipients = AHashSet::new();
    let mut copy_components = AHashSet::new();
    let mut scheduling_component_ids = Vec::with_capacity(itip.components.len());

    for comp in itip.components.into_values() {
        // Prepare component for iTIP
        let orig_component = &ical.components[comp.comp_id as usize];
        let mut component = itip_export_component(
            orig_component,
            itip.uid,
            &dt_stamp,
            sequence,
            Some(&ICalendarParticipationStatus::NeedsAction),
        );
        scheduling_component_ids.push(comp.comp_id);

        // Add VALARM sub-components
        if include_alarms {
            for sub_comp_id in &orig_component.component_ids {
                if matches!(
                    ical.components[*sub_comp_id as usize].component_type,
                    ICalendarComponentType::VAlarm
                ) {
                    copy_components.insert(*sub_comp_id);
                    component.component_ids.push(*sub_comp_id);
                }
            }
        }

        // Add component to message
        message.components[comp.comp_id as usize] = component;
        message.components[0].component_ids.push(comp.comp_id);

        // Add attendees
        for attendee in comp.attendees {
            if attendee.send_scheduling_messages() {
                recipients.insert(attendee.email.email);
            }
        }
    }

    // Copy timezones and alarms
    for (comp_id, comp) in ical.components.iter().enumerate() {
        if matches!(comp.component_type, ICalendarComponentType::VTimezone) {
            copy_components.extend(comp.component_ids.iter().copied());
        } else if !copy_components.contains(&(comp_id as u16)) {
            continue;
        }
        message.components.push(comp.clone());
        message.components[0].component_ids.push(comp_id as u16);
    }

    if !recipients.is_empty() {
        Ok(ItipMessage {
            method: ICalendarMethod::Request,
            from: itip.organizer.email.email,
            to: recipients.into_iter().collect(),
            changed_properties: vec![],
            message,
        })
    } else {
        Err(ItipError::NothingToSend)
    }
}
