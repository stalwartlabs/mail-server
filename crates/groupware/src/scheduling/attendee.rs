/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarMethod, ICalendarParameter,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarValue,
    },
    scheduling::{
        itip::{itip_build_envelope, itip_export_component},
        Email, InstanceId, ItipEntryValue, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots,
        SchedulingInfo,
    },
};
use ahash::AHashSet;

pub(crate) fn attendee_handle_update(
    old_ical: &ICalendar,
    new_ical: &ICalendar,
    old_itip: ItipSnapshots<'_>,
    new_itip: ItipSnapshots<'_>,
    info: &mut SchedulingInfo,
) -> Result<ItipMessage, ItipError> {
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: Vec::with_capacity(2),
    };
    message
        .components
        .push(itip_build_envelope(ICalendarMethod::Reply));

    let mut mail_from = None;
    let mut email_rcpt = AHashSet::new();
    let mut tz_resolver = None;

    for (instance_id, instance) in &new_itip.components {
        if let Some(old_instance) = old_itip.components.get(instance_id) {
            match (instance.local_attendee(), old_instance.local_attendee()) {
                (Some(attendee), Some(old_attendee)) if attendee.email == old_attendee.email => {
                    // Check added fields
                    for new_entry in old_instance.entries.difference(&instance.entries) {
                        match (new_entry.name, &new_entry.value) {
                            (ICalendarProperty::Exdate, ItipEntryValue::DateTime(udt))
                                if instance_id == &InstanceId::Main =>
                            {
                                if let Some(date) = udt.date.to_date_time_with_tz(
                                    tz_resolver
                                        .get_or_insert_with(|| old_ical.build_tz_resolver())
                                        .resolve(udt.tz_id),
                                ) {
                                    if let Some((mut cancel_comp, attendee_email)) =
                                        attendee_decline(
                                            old_ical,
                                            instance_id,
                                            &old_itip,
                                            old_instance,
                                            &dt_stamp,
                                            info.sequence,
                                            &mut email_rcpt,
                                        )
                                    {
                                        // Add EXDATE as RECURRENCE-ID
                                        cancel_comp.add_property(
                                            ICalendarProperty::RecurrenceId,
                                            ICalendarValue::PartialDateTime(Box::new(
                                                PartialDateTime::from_utc_timestamp(
                                                    date.timestamp(),
                                                ),
                                            )),
                                        );

                                        // Add cancel component
                                        let comp_id = message.components.len() as u16;
                                        message.components[0].component_ids.push(comp_id);
                                        message.components.push(cancel_comp);
                                        mail_from = Some(&attendee_email.email);
                                    }
                                } else {
                                    return Err(ItipError::ChangeNotAllowed);
                                }
                            }
                            (
                                ICalendarProperty::Exdate
                                | ICalendarProperty::Summary
                                | ICalendarProperty::Description,
                                _,
                            ) => {}
                            _ => {
                                // Adding these properties is not allowed
                                return Err(ItipError::ChangeNotAllowed);
                            }
                        }
                    }

                    // Send participation status update
                    if attendee.is_server_scheduling
                        && ((attendee.part_stat != old_attendee.part_stat)
                            || attendee.force_send.is_some())
                    {
                        // A new instance has been added
                        let comp_id = message.components.len() as u16;
                        message.components[0].component_ids.push(comp_id);
                        message.components.push(itip_export_component(
                            &new_ical.components[instance.comp_id as usize],
                            new_itip.uid,
                            &dt_stamp,
                            info.sequence,
                            None,
                        ));
                        mail_from = Some(&attendee.email.email);
                    }

                    // Check removed fields
                    for removed_entry in instance.entries.difference(&old_instance.entries) {
                        if !matches!(
                            removed_entry.name,
                            ICalendarProperty::Exdate
                                | ICalendarProperty::Summary
                                | ICalendarProperty::Description
                        ) {
                            // Removing these properties is not allowed
                            return Err(ItipError::ChangeNotAllowed);
                        }
                    }
                }
                _ => {
                    // Change in local attendee email is not allowed
                    return Err(ItipError::ChangeNotAllowed);
                }
            }
        } else if let Some(local_attendee) = instance
            .local_attendee()
            .filter(|_| instance_id != &InstanceId::Main)
        {
            // A new instance has been added
            let comp_id = message.components.len() as u16;
            message.components[0].component_ids.push(comp_id);
            message.components.push(itip_export_component(
                &new_ical.components[instance.comp_id as usize],
                new_itip.uid,
                &dt_stamp,
                info.sequence,
                None,
            ));
            mail_from = Some(&local_attendee.email.email);
        } else {
            return Err(ItipError::ChangeNotAllowed);
        }
    }

    for (instance_id, old_instance) in &old_itip.components {
        if !new_itip.components.contains_key(instance_id) {
            if instance_id != &InstanceId::Main && old_instance.has_local_attendee() {
                // Send cancel message for removed instances
                if let Some((cancel_comp, attendee_email)) = attendee_decline(
                    old_ical,
                    instance_id,
                    &old_itip,
                    old_instance,
                    &dt_stamp,
                    info.sequence,
                    &mut email_rcpt,
                ) {
                    // Add cancel component
                    let comp_id = message.components.len() as u16;
                    message.components[0].component_ids.push(comp_id);
                    message.components.push(cancel_comp);
                    mail_from = Some(&attendee_email.email);
                }
            } else {
                // Removing instances is not allowed
                return Err(ItipError::ChangeNotAllowed);
            }
        }
    }

    if let Some(from) = mail_from {
        email_rcpt.insert(&new_itip.organizer.email.email);

        Ok(ItipMessage {
            method: ICalendarMethod::Reply,
            from: from.to_string(),
            to: email_rcpt.into_iter().map(|e| e.to_string()).collect(),
            changed_properties: vec![],
            message,
        })
    } else {
        Err(ItipError::NothingToSend)
    }
}

pub(crate) fn attendee_decline<'x>(
    ical: &'x ICalendar,
    instance_id: &'x InstanceId<'x>,
    itip: &'x ItipSnapshots<'x>,
    comp: &'x ItipSnapshot<'x>,
    dt_stamp: &'x PartialDateTime,
    sequence: u32,
    email_rcpt: &mut AHashSet<&'x str>,
) -> Option<(ICalendarComponent, &'x Email)> {
    let component = &ical.components[comp.comp_id as usize];
    let mut cancel_comp = ICalendarComponent {
        component_type: component.component_type.clone(),
        entries: Vec::with_capacity(5),
        component_ids: vec![],
    };

    let mut local_attendee = None;
    let mut delegated_from = None;

    for attendee in &comp.attendees {
        if attendee.email.is_local {
            if attendee.is_server_scheduling
                && attendee.rsvp.is_none_or(|rsvp| rsvp)
                && (attendee.force_send.is_some()
                    || !matches!(
                        attendee.part_stat,
                        Some(
                            ICalendarParticipationStatus::Declined
                                | ICalendarParticipationStatus::Delegated
                        )
                    ))
            {
                local_attendee = Some(attendee);
            }
        } else if attendee.delegated_to.iter().any(|d| d.is_local) {
            cancel_comp
                .entries
                .push(component.entries[attendee.entry_id as usize].clone());
            delegated_from = Some(&attendee.email.email);
        }
    }

    local_attendee.map(|local_attendee| {
        cancel_comp.add_property(
            ICalendarProperty::Organizer,
            ICalendarValue::Text(itip.organizer.email.to_string()),
        );
        cancel_comp.add_property_with_params(
            ICalendarProperty::Attendee,
            [ICalendarParameter::Partstat(
                ICalendarParticipationStatus::Declined,
            )],
            ICalendarValue::Text(local_attendee.email.to_string()),
        );
        cancel_comp.add_uid(itip.uid);
        cancel_comp.add_dtstamp(dt_stamp.clone());
        cancel_comp.add_sequence(sequence);

        if let InstanceId::Recurrence(recurrence_id) = instance_id {
            cancel_comp
                .entries
                .push(component.entries[recurrence_id.entry_id as usize].clone());
        }
        if let Some(delegated_from) = delegated_from {
            email_rcpt.insert(delegated_from);
        }

        (cancel_comp, &local_attendee.email)
    })
}
