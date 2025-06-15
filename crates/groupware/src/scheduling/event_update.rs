/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    icalendar::ICalendar,
    scheduling::{
        attendee::attendee_handle_update, event_cancel::itip_cancel, itip::itip_finalize,
        organizer::organizer_handle_update, snapshot::itip_snapshot, ItipError, ItipMessage,
    },
};

pub fn itip_update(
    ical: &mut ICalendar,
    old_ical: &mut ICalendar,
    account_emails: &[&str],
) -> Result<ItipMessage, ItipError> {
    let old_itip = itip_snapshot(old_ical, account_emails, false)?;
    match itip_snapshot(ical, account_emails, false) {
        Ok(new_itip) => {
            let mut sequences = Vec::new();
            if old_itip.organizer.email != new_itip.organizer.email {
                // RFC 6638 does not support replacing the organizer
                Err(ItipError::OrganizerMismatch)
            } else if old_itip.organizer.email.is_local {
                organizer_handle_update(old_ical, ical, old_itip, new_itip, &mut sequences)
            } else {
                attendee_handle_update(old_ical, ical, old_itip, new_itip)
            }
            .inspect(|_| {
                itip_finalize(ical, &sequences);
            })
        }
        Err(err) => {
            match &err {
                ItipError::NoSchedulingInfo
                | ItipError::NotOrganizer
                | ItipError::NotOrganizerNorAttendee
                | ItipError::OtherSchedulingAgent => {
                    if old_itip.organizer.email.is_local {
                        // RFC 6638 does not support replacing the organizer, so we cancel the event
                        itip_cancel(old_ical, account_emails)
                    } else {
                        Err(ItipError::ChangeNotAllowed)
                    }
                }
                _ => Err(err),
            }
        }
    }
}
