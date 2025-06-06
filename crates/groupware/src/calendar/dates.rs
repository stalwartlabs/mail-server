/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEventData, ArchivedTimezone, CalendarEventData, Timezone,
    alarm::{CalendarAlarm, ExpandAlarm},
};
use crate::calendar::ComponentTimeRange;
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponentType, dates::TimeOrDelta},
};
use compact_str::ToCompactString;
use store::{
    ahash::AHashMap,
    write::{key::KeySerializer, now},
};

impl CalendarEventData {
    pub fn new(
        ical: ICalendar,
        default_tz: Tz,
        max_expansions: usize,
        next_email_alarm: &mut Option<CalendarAlarm>,
    ) -> Self {
        let mut ranges = TimeRanges::default();
        let now = now() as i64;

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
            for alarm in alarms.entry(event.comp_id).or_insert_with(|| {
                ical.component_by_id(event.comp_id)
                    .map_or(&[][..], |c| c.component_ids.as_slice())
                    .iter()
                    .filter_map(|alarm_id| {
                        ical.component_by_id(*alarm_id).and_then(|alarm| {
                            if alarm.component_type == ICalendarComponentType::VAlarm {
                                alarm.expand_alarm(*alarm_id, event.comp_id)
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            }) {
                if let Some(alarm_time) =
                    alarm
                        .delta
                        .to_timestamp(start_timestamp_utc, end_timestamp_utc, default_tz)
                {
                    if alarm_time < min {
                        min = alarm_time;
                    }
                    if alarm_time > max {
                        max = alarm_time;
                    }
                    if alarm.is_email_alert && alarm_time > now {
                        if let Some(next) = next_email_alarm {
                            if alarm_time < next.alarm_time {
                                *next = CalendarAlarm {
                                    alarm_id: alarm.id,
                                    event_id: alarm.parent_id,
                                    alarm_time,
                                    event_start: start_timestamp_naive,
                                    event_end: end_timestamp_naive,
                                    event_start_tz: start_tz,
                                    event_end_tz: end_tz,
                                };
                            }
                        } else {
                            *next_email_alarm = Some(CalendarAlarm {
                                alarm_id: alarm.id,
                                event_id: alarm.parent_id,
                                alarm_time,
                                event_start: start_timestamp_naive,
                                event_end: end_timestamp_naive,
                                event_start_tz: start_tz,
                                event_end_tz: end_tz,
                            });
                        }
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

        if !expanded.errors.is_empty() {
            trc::event!(
                Calendar(trc::CalendarEvent::RuleExpansionError),
                Reason = expanded
                    .errors
                    .into_iter()
                    .map(|e| e.error.to_compact_string())
                    .collect::<Vec<_>>(),
                Details = ical.to_string(),
                Limit = max_expansions,
            );
        }

        CalendarEventData {
            event: ical,
            time_ranges: events.into_boxed_slice(),
            alarms: alarms
                .into_values()
                .flatten()
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
