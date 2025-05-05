/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Alarm, AlarmDelta, ArchivedAlarmDelta, ArchivedCalendarEventData, ArchivedTimezone,
    CalendarEventData, Timezone,
};
use crate::calendar::ComponentTimeRange;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarParameter, ICalendarProperty, ICalendarValue,
        Related,
        dates::{CalendarEvent, TimeOrDelta},
    },
};
use chrono::{DateTime, TimeZone};
use dav_proto::schema::property::TimeRange;
use rkyv::time;
use std::str::FromStr;
use store::{
    ahash::AHashMap,
    write::{bitpack::BitpackIterator, key::KeySerializer},
};
use utils::codec::leb128::Leb128Reader;

impl CalendarEventData {
    pub fn new(ical: ICalendar, default_tz: Tz, max_expansions: usize) -> Self {
        let mut ranges = TimeRanges::default();

        let expanded = ical.expand_dates(default_tz, max_expansions);
        let mut groups: AHashMap<(u16, u16, u16, i32), Vec<i64>> = AHashMap::with_capacity(16);
        let mut alarms = AHashMap::with_capacity(16);

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

            // Expand alarms
            let mut min = std::cmp::min(start_timestamp_utc, end_timestamp_utc);
            let mut max = std::cmp::max(start_timestamp_utc, end_timestamp_utc);
            for alarm_delta in alarms.entry(event.comp_id).or_insert_with(|| {
                ical.alarms_for_id(event.comp_id)
                    .filter_map(|alarm| alarm.expand_alarm())
                    .collect::<Vec<_>>()
                    .into_boxed_slice()
            }) {
                if let Some(alarm_time) =
                    alarm_delta.to_timestamp(start_timestamp_utc, end_timestamp_utc, default_tz)
                {
                    if alarm_time < min {
                        min = alarm_time;
                    }
                    if alarm_time > max {
                        max = alarm_time;
                    }
                }
            }

            ranges.update_base_offset(start_timestamp_naive, end_timestamp_naive);
            ranges.update_utc_min_max(min, max);
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
                    debug_assert!(instance >= ranges.base_offset);
                    instance_offsets.push((instance - ranges.base_offset) as u32);
                }

                KeySerializer::new(instance_offsets.len() * std::mem::size_of::<u32>())
                    .bitpack_sorted(&instance_offsets)
                    .finalize()
            } else {
                KeySerializer::new(std::mem::size_of::<u32>())
                    .write_leb128((instances.first().unwrap() - ranges.base_offset) as u32)
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
            event: ical,
            time_ranges: events.into_boxed_slice(),
            alarms: alarms
                .into_iter()
                .filter_map(|(comp_id, alarms)| {
                    if !alarms.is_empty() {
                        Some(Alarm { comp_id, alarms })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
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

#[derive(Default, Debug)]
struct TimeRanges {
    max_time_utc: i64,
    min_time_utc: i64,
    base_offset: i64,
}

impl TimeRanges {
    pub fn update_base_offset(&mut self, t1: i64, t2: i64) {
        let offset = std::cmp::min(t1, t2);
        if offset < self.base_offset || self.base_offset == 0 {
            self.base_offset = offset;
        }
    }

    pub fn update_utc_min_max(&mut self, min: i64, max: i64) {
        if min < self.min_time_utc || self.min_time_utc == 0 {
            self.min_time_utc = min;
        }
        if max > self.max_time_utc {
            self.max_time_utc = max;
        }
        if min < self.base_offset || self.base_offset == 0 {
            self.base_offset = min;
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

pub trait ExpandAlarm {
    fn expand_alarm(&self) -> Option<AlarmDelta>;
}

impl ExpandAlarm for ICalendarComponent {
    fn expand_alarm(&self) -> Option<AlarmDelta> {
        for entry in self.entries.iter() {
            if matches!(entry.name, ICalendarProperty::Trigger) {
                let mut tz = None;
                let mut trigger_start = true;

                for param in entry.params.iter() {
                    match param {
                        ICalendarParameter::Related(related) => {
                            trigger_start = matches!(related, Related::Start);
                        }
                        ICalendarParameter::Tzid(tz_id) => {
                            tz = Tz::from_str(tz_id).ok();
                        }
                        _ => {}
                    }
                }

                return match entry.values.first()? {
                    ICalendarValue::PartialDateTime(dt) => {
                        let tz = tz.unwrap_or(Tz::Floating);

                        dt.to_date_time_with_tz(tz).map(|dt| {
                            let timestamp = dt.timestamp();
                            if !dt.timezone().is_floating() {
                                AlarmDelta::FixedUtc(timestamp)
                            } else {
                                AlarmDelta::FixedFloating(timestamp)
                            }
                        })
                    }
                    ICalendarValue::Duration(duration) => {
                        if trigger_start {
                            Some(AlarmDelta::Start(duration.as_seconds()))
                        } else {
                            Some(AlarmDelta::End(duration.as_seconds()))
                        }
                    }
                    _ => None,
                };
            }
        }

        None
    }
}

impl AlarmDelta {
    pub fn to_timestamp(&self, start: i64, end: i64, default_tz: Tz) -> Option<i64> {
        match self {
            AlarmDelta::Start(delta) => Some(start + delta),
            AlarmDelta::End(delta) => Some(end + delta),
            AlarmDelta::FixedUtc(timestamp) => Some(*timestamp),
            AlarmDelta::FixedFloating(timestamp) => default_tz
                .from_local_datetime(&DateTime::from_timestamp(*timestamp, 0)?.naive_local())
                .single()
                .map(|dt| dt.timestamp()),
        }
    }
}

impl ArchivedAlarmDelta {
    pub fn to_timestamp(&self, start: i64, end: i64, default_tz: Tz) -> Option<i64> {
        match self {
            ArchivedAlarmDelta::Start(delta) => Some(start + delta.to_native()),
            ArchivedAlarmDelta::End(delta) => Some(end + delta.to_native()),
            ArchivedAlarmDelta::FixedUtc(timestamp) => Some(timestamp.to_native()),
            ArchivedAlarmDelta::FixedFloating(timestamp) => default_tz
                .from_local_datetime(
                    &DateTime::from_timestamp(timestamp.to_native(), 0)?.naive_local(),
                )
                .single()
                .map(|dt| dt.timestamp()),
        }
    }
}
