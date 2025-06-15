/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarMethod, ICalendarProperty,
        ICalendarValue,
    },
    scheduling::{
        attendee::attendee_decline,
        itip::{itip_add_tz, itip_build_envelope, itip_finalize},
        snapshot::itip_snapshot,
        Email, InstanceId, ItipError, ItipMessage, ItipSnapshot, ItipSnapshots,
    },
};
use ahash::AHashSet;

pub fn itip_cancel(
    ical: &mut ICalendar,
    account_emails: &[&str],
) -> Result<ItipMessage, ItipError> {
    // Prepare iTIP message
    let itip = itip_snapshot(ical, account_emails, false)?;
    let dt_stamp = PartialDateTime::now();
    let mut message = ICalendar {
        components: Vec::with_capacity(2),
    };

    if itip.organizer.email.is_local {
        // Send cancel message
        let mut comp = itip_build_envelope(ICalendarMethod::Cancel);
        comp.component_ids.push(1);
        message.components.push(comp);

        // Fetch guest emails
        let mut recipients = AHashSet::new();
        let mut cancel_guests = AHashSet::new();
        let mut component_type = &ICalendarComponentType::VEvent;
        let mut increment_sequences = Vec::new();
        let mut sequence = 0;
        for (instance_id, comp) in &itip.components {
            component_type = &ical.components[comp.comp_id as usize].component_type;
            for attendee in &comp.attendees {
                if attendee.send_update_messages() {
                    recipients.insert(attendee.email.email.clone());
                }
                cancel_guests.insert(&attendee.email);
            }

            // Increment sequence if needed
            increment_sequences.push(comp.comp_id);
            if instance_id == &InstanceId::Main {
                sequence = comp.sequence.unwrap_or_default() + 1;
            }
        }

        if !recipients.is_empty() && component_type != &ICalendarComponentType::VFreebusy {
            message.components.push(build_cancel_component(
                component_type.clone(),
                &itip,
                sequence,
                dt_stamp,
                cancel_guests,
            ));
            let message = ItipMessage {
                method: ICalendarMethod::Cancel,
                from: itip.organizer.email.email,
                to: recipients.into_iter().collect(),
                changed_properties: vec![],
                message,
            };

            itip_finalize(ical, &increment_sequences);

            Ok(message)
        } else {
            Err(ItipError::NothingToSend)
        }
    } else {
        // Send decline message
        message
            .components
            .push(itip_build_envelope(ICalendarMethod::Reply));

        // Decline attendance for all instances that have local attendees
        let mut mail_from = None;
        let mut email_rcpt = AHashSet::new();
        for (instance_id, comp) in &itip.components {
            if let Some((cancel_comp, attendee_email)) =
                attendee_decline(ical, instance_id, &itip, comp, &dt_stamp, &mut email_rcpt)
            {
                // Add cancel component
                let comp_id = message.components.len() as u16;
                message.components[0].component_ids.push(comp_id);
                message.components.push(cancel_comp);
                mail_from = Some(&attendee_email.email);
            }
        }

        if let Some(from) = mail_from {
            // Add timezone information if needed
            itip_add_tz(&mut message, ical);

            email_rcpt.insert(&itip.organizer.email.email);
            let message = ItipMessage {
                method: ICalendarMethod::Reply,
                from: from.to_string(),
                to: email_rcpt.into_iter().map(|e| e.to_string()).collect(),
                changed_properties: vec![],
                message,
            };

            itip_finalize(ical, &[]);

            Ok(message)
        } else {
            Err(ItipError::NothingToSend)
        }
    }
}

pub(crate) fn cancel_component<'x>(
    ical: &'x ICalendar,
    itip: &'x ItipSnapshots<'x>,
    comp: &'x ItipSnapshot<'x>,
    sequence: i64,
    dt_stamp: PartialDateTime,
    recipients: &mut AHashSet<&'x str>,
) -> Option<ICalendarComponent> {
    let component_type = &ical.components[comp.comp_id as usize].component_type;
    let mut cancel_guests = AHashSet::new();
    let mut has_recipients = false;

    for attendee in &comp.attendees {
        if attendee.send_update_messages() {
            recipients.insert(attendee.email.email.as_str());
            has_recipients = true;
        }
        cancel_guests.insert(&attendee.email);
    }

    if has_recipients && component_type != &ICalendarComponentType::VFreebusy {
        Some(build_cancel_component(
            component_type.clone(),
            itip,
            sequence,
            dt_stamp,
            cancel_guests,
        ))
    } else {
        None
    }
}

fn build_cancel_component(
    component_type: ICalendarComponentType,
    itip: &ItipSnapshots<'_>,
    sequence: i64,
    dt_stamp: PartialDateTime,
    cancel_guests: AHashSet<&Email>,
) -> ICalendarComponent {
    let mut cancel_comp = ICalendarComponent {
        component_type,
        entries: Vec::with_capacity(cancel_guests.len() + 5),
        component_ids: vec![],
    };
    cancel_comp.add_property(
        ICalendarProperty::Method,
        ICalendarValue::Method(ICalendarMethod::Cancel),
    );
    cancel_comp.add_dtstamp(dt_stamp);
    cancel_comp.add_sequence(sequence);
    cancel_comp.add_uid(itip.uid);
    cancel_comp.add_property(
        ICalendarProperty::Organizer,
        ICalendarValue::Text(itip.organizer.email.to_string()),
    );

    for email in cancel_guests {
        cancel_comp.add_property(
            ICalendarProperty::Attendee,
            ICalendarValue::Text(email.to_string()),
        );
    }
    cancel_comp
}
