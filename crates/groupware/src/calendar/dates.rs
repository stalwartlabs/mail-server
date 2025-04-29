/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedCalendarEventData, ArchivedTimezone, CalendarEventData, Timezone};
use crate::calendar::ComponentTimeRange;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar,
        dates::{CalendarEvent, TimeOrDelta},
    },
};
use chrono::{DateTime, TimeZone};
use dav_proto::schema::property::TimeRange;
use store::{
    ahash::AHashMap,
    write::{bitpack::BitpackIterator, key::KeySerializer},
};
use utils::codec::leb128::Leb128Reader;

impl CalendarEventData {
    pub fn new(event: ICalendar, max_expansions: usize) -> Self {
        let mut ranges = TimeRanges::default();

        let expanded = event.expand_dates(Tz::Floating, max_expansions);
        let mut groups: AHashMap<(u16, u16, u16, i32), Vec<i64>> = AHashMap::with_capacity(16);

        for event in expanded.events {
            let start_naive = event.start.naive_local();
            let start_tz = event.start.timezone().as_id();
            let start_timestamp_utc = event.start.timestamp();
            let start_timestamp_naive = start_naive.and_utc().timestamp();
            let (end_timestamp_utc, end_timestamp_naive, end_tz) = match event.end {
                TimeOrDelta::Time(time) => {
                    let end_naive = time.naive_local();
                    let end_timestamp_utc = time.timestamp();
                    let end_timestamp_naive = end_naive.and_utc().timestamp();
                    (
                        end_timestamp_utc,
                        end_timestamp_naive,
                        time.timezone().as_id(),
                    )
                }
                TimeOrDelta::Delta(delta) => {
                    let delta = delta.num_seconds();
                    (
                        start_timestamp_utc + delta,
                        start_timestamp_naive + delta,
                        start_tz,
                    )
                }
            };
            ranges.update(start_timestamp_utc, start_timestamp_naive);
            ranges.update(end_timestamp_utc, end_timestamp_naive);
            groups
                .entry((
                    start_tz,
                    end_tz,
                    event.comp_id,
                    (end_timestamp_naive - start_timestamp_naive) as i32,
                ))
                .or_default()
                .push(start_timestamp_naive);
        }

        let mut events = Vec::with_capacity(groups.len());
        for ((start_tz, end_tz, id, duration), mut instances) in groups {
            let instances = if instances.len() > 1 {
                instances.sort_unstable();
                // Bitpack instances
                let mut instance_offsets = Vec::with_capacity(instances.len());
                for instance in instances {
                    instance_offsets.push((ranges.base_offset - instance) as u32);
                }
                KeySerializer::new(instance_offsets.len() * std::mem::size_of::<u32>())
                    .bitpack_sorted(&instance_offsets)
                    .finalize()
            } else {
                KeySerializer::new(std::mem::size_of::<u32>())
                    .write_leb128((ranges.base_offset - instances.first().unwrap()) as u32)
                    .finalize()
            };

            events.push(ComponentTimeRange {
                id,
                start_tz,
                end_tz,
                duration,
                instances: instances.into_boxed_slice(),
            });
        }

        for error in expanded.errors {
            let todo = "log me";
        }

        CalendarEventData {
            event,
            time_ranges: events.into_boxed_slice(),
            base_offset: ranges.base_offset,
            base_time_utc: (ranges.min_time_utc - ranges.base_offset) as u32,
            duration: (ranges.max_time_utc - ranges.min_time_utc) as u32,
        }
    }

    pub fn event_range(&self) -> Option<(i64, u32)> {
        if self.base_offset != 0 {
            Some((self.base_offset + self.base_time_utc as i64, self.duration))
        } else {
            None
        }
    }
}

impl ArchivedCalendarEventData {
    pub fn expand(&self, default_tz: Tz, limit: TimeRange) -> Option<Vec<CalendarEvent<i64, i64>>> {
        let mut expansion = Vec::with_capacity(self.time_ranges.len());
        let base_offset = self.base_offset.to_native();
        let expansion_limit = limit.start..=limit.end;

        for range in self.time_ranges.iter() {
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

                    if expansion_limit.contains(&start) || expansion_limit.contains(&end) {
                        expansion.push(CalendarEvent {
                            comp_id,
                            start,
                            end,
                        });
                    } else if end > limit.end {
                        break;
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

                if expansion_limit.contains(&start) || expansion_limit.contains(&end) {
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

#[derive(Default)]
struct TimeRanges {
    max_time_utc: i64,
    min_time_utc: i64,
    base_offset: i64,
}

impl TimeRanges {
    pub fn update(&mut self, utc_timestamp: i64, naive_timestamp: i64) {
        if utc_timestamp > self.max_time_utc {
            self.max_time_utc = utc_timestamp;
        }
        if utc_timestamp < self.min_time_utc || self.max_time_utc == 0 {
            self.min_time_utc = utc_timestamp;
        }
        let offset = std::cmp::min(utc_timestamp, naive_timestamp);
        if offset < self.base_offset || self.base_offset == 0 {
            self.base_offset = offset;
        }
    }
}

impl ArchivedCalendarEventData {
    pub fn event_range(&self) -> Option<(i64, u32)> {
        if self.base_offset != 0 {
            Some((
                self.base_offset.to_native() + self.base_time_utc.to_native() as i64,
                self.duration.to_native(),
            ))
        } else {
            None
        }
    }
}

impl Timezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            Timezone::IANA(iana) => Tz::from_id(*iana),
            Timezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            Timezone::Default => None,
        }
    }
}

impl ArchivedTimezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            ArchivedTimezone::IANA(iana) => Tz::from_id(iana.to_native()),
            ArchivedTimezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            ArchivedTimezone::Default => None,
        }
    }
}
