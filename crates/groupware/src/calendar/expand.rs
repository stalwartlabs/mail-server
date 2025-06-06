/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{common::timezone::Tz, icalendar::dates::CalendarEvent};
use chrono::{DateTime, TimeZone};
use dav_proto::schema::property::TimeRange;
use store::write::bitpack::BitpackIterator;
use utils::codec::leb128::Leb128Reader;

use super::ArchivedCalendarEventData;

impl ArchivedCalendarEventData {
    pub fn expand(&self, default_tz: Tz, limit: TimeRange) -> Option<Vec<CalendarEvent<i64, i64>>> {
        let mut expansion = Vec::with_capacity(self.time_ranges.len());
        let base_offset = self.base_offset.to_native();

        'outer: for range in self.time_ranges.iter() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;

            let comp_id = range.id.to_native();
            let duration = range.duration.to_native() as i64;
            let mut start_tz = Tz::from_id(range.start_tz.to_native())?;
            let mut end_tz = Tz::from_id(range.end_tz.to_native())?;

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            if instances.len() > bytes_read {
                // Recurring event
                let unpacker =
                    BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
                for start_offset in unpacker {
                    let start_date_naive = start_offset as i64 + base_offset;
                    let end_date_naive = start_date_naive + duration;
                    let start = start_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();
                    let end = end_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();

                    if ((start < limit.end) || (start <= limit.start))
                        && (end > limit.start || end >= limit.end)
                    {
                        expansion.push(CalendarEvent {
                            comp_id,
                            start,
                            end,
                        });
                    } else if start > limit.end {
                        continue 'outer;
                    }
                }
            } else {
                // Single event
                let start_date_naive = offset_or_count as i64 + base_offset;
                let end_date_naive = start_date_naive + duration;
                let start = start_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();
                let end = end_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();

                if ((start < limit.end) || (start <= limit.start))
                    && (end > limit.start || end >= limit.end)
                {
                    expansion.push(CalendarEvent {
                        comp_id,
                        start,
                        end,
                    });
                }
            }
        }

        Some(expansion)
    }
}
