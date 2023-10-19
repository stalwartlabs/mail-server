/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::time::Duration;

use chrono::{Datelike, TimeZone, Timelike};

use super::utils::ParseValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleCron {
    Day { hour: u32, minute: u32 },
    Week { day: u32, hour: u32, minute: u32 },
    Hour { minute: u32 },
}

impl SimpleCron {
    pub fn time_to_next(&self) -> Duration {
        let now = chrono::Local::now();
        let next = match self {
            SimpleCron::Day { hour, minute } => {
                let next = chrono::Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .unwrap();
                if next < now {
                    next + chrono::Duration::days(1)
                } else {
                    next
                }
            }
            SimpleCron::Week { day, hour, minute } => {
                let next = chrono::Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .unwrap();
                if next < now {
                    next + chrono::Duration::days(
                        (7 - now.weekday().number_from_monday() + *day).into(),
                    )
                } else {
                    next
                }
            }
            SimpleCron::Hour { minute } => {
                let next = chrono::Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), now.hour(), *minute, 0)
                    .unwrap();
                if next < now {
                    next + chrono::Duration::hours(1)
                } else {
                    next
                }
            }
        };

        (next - now).to_std().unwrap()
    }
}

impl ParseValue for SimpleCron {
    fn parse_value(key: impl super::utils::AsKey, value: &str) -> super::Result<Self> {
        let mut hour = 0;
        let mut minute = 0;
        let key = key.as_key();

        for (pos, value) in value.split(' ').enumerate() {
            if pos == 0 {
                minute = value.parse::<u32>().map_err(|_| {
                    format!("Invalid cron key {key:?}: failed to parse cron minute")
                })?;
                if !(0..=59).contains(&minute) {
                    return Err(format!(
                        "Invalid cron key {key:?}: failed to parse minute, invalid value: {minute}"
                    ));
                }
            } else if pos == 1 {
                if value.as_bytes().first().ok_or_else(|| {
                    format!("Invalid cron key {key:?}: failed to parse cron weekday")
                })? == &b'*'
                {
                    return Ok(SimpleCron::Hour { minute });
                } else {
                    hour = value.parse::<u32>().map_err(|_| {
                        format!("Invalid cron key {key:?}: failed to parse cron hour")
                    })?;
                    if !(0..=23).contains(&hour) {
                        return Err(format!(
                            "Invalid cron key {key:?}: failed to parse hour, invalid value: {hour}"
                        ));
                    }
                }
            } else if pos == 2 {
                if value.as_bytes().first().ok_or_else(|| {
                    format!("Invalid cron key {key:?}: failed to parse cron weekday")
                })? == &b'*'
                {
                    return Ok(SimpleCron::Day { hour, minute });
                } else {
                    let day = value.parse::<u32>().map_err(|_| {
                        format!("Invalid cron key {key:?}: failed to parse cron weekday")
                    })?;
                    if !(1..=7).contains(&hour) {
                        return Err(format!(
                            "Invalid cron key {key:?}: failed to parse weekday, invalid value: {}, range is 1 (Monday) to 7 (Sunday).",
                            hour,
                        ));
                    }

                    return Ok(SimpleCron::Week { day, hour, minute });
                }
            }
        }

        Err(format!("Invalid cron key {key:?}: parse cron expression."))
    }
}
