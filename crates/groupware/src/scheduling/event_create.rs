/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    icalendar::ICalendar,
    scheduling::{
        organizer::organizer_request_full, snapshot::itip_snapshot, ItipError, ItipMessage,
        SchedulingInfo,
    },
};

pub fn itip_create(
    ical: &ICalendar,
    account_emails: &[&str],
    info: &mut SchedulingInfo,
) -> Result<ItipMessage, ItipError> {
    let itip = itip_snapshot(ical, account_emails, false)?;
    if !itip.organizer.is_server_scheduling {
        Err(ItipError::OtherSchedulingAgent)
    } else if !itip.organizer.email.is_local {
        Err(ItipError::NotOrganizer)
    } else {
        let sequence = std::cmp::max(itip.sequence.unwrap_or_default() as u32, info.sequence) + 1;
        organizer_request_full(ical, itip, sequence, true).inspect(|_| {
            info.sequence = sequence;
        })
    }
}
