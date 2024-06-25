/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use chrono::{Datelike, Local, TimeDelta, TimeZone, Timelike};

use super::utils::ParseValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleCron {
    Day { hour: u32, minute: u32 },
    Week { day: u32, hour: u32, minute: u32 },
    Hour { minute: u32 },
}

impl SimpleCron {
    pub fn time_to_next(&self) -> Duration {
        let now = Local::now();
        let next = match self {
            SimpleCron::Day { hour, minute } => {
                let next = Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .earliest()
                    .unwrap_or_else(|| now - TimeDelta::try_seconds(1).unwrap_or_default());
                if next <= now {
                    next + TimeDelta::try_days(1).unwrap_or_default()
                } else {
                    next
                }
            }
            SimpleCron::Week { day, hour, minute } => {
                let next = Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), *hour, *minute, 0)
                    .earliest()
                    .unwrap_or_else(|| now - TimeDelta::try_seconds(1).unwrap_or_default());
                if next <= now {
                    next + TimeDelta::try_days(
                        (7 - now.weekday().number_from_monday() + *day).into(),
                    )
                    .unwrap_or_default()
                } else {
                    next
                }
            }
            SimpleCron::Hour { minute } => {
                let next = Local
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), now.hour(), *minute, 0)
                    .earliest()
                    .unwrap_or_else(|| now - TimeDelta::try_seconds(1).unwrap_or_default());
                if next <= now {
                    next + TimeDelta::try_hours(1).unwrap_or_default()
                } else {
                    next
                }
            }
        };

        (next - now).to_std().unwrap()
    }
}

impl ParseValue for SimpleCron {
    fn parse_value(value: &str) -> super::Result<Self> {
        let mut hour = 0;
        let mut minute = 0;

        for (pos, value) in value.split(' ').enumerate() {
            if pos == 0 {
                minute = value
                    .parse::<u32>()
                    .map_err(|_| "Invalid cron key: failed to parse cron minute".to_string())?;
                if !(0..=59).contains(&minute) {
                    return Err(format!(
                        "Invalid cron key: failed to parse minute, invalid value: {minute}"
                    ));
                }
            } else if pos == 1 {
                if value
                    .as_bytes()
                    .first()
                    .ok_or_else(|| "Invalid cron key: failed to parse cron hour".to_string())?
                    == &b'*'
                {
                    return Ok(SimpleCron::Hour { minute });
                } else {
                    hour = value
                        .parse::<u32>()
                        .map_err(|_| "Invalid cron key: failed to parse cron hour".to_string())?;
                    if !(0..=23).contains(&hour) {
                        return Err(format!(
                            "Invalid cron key: failed to parse hour, invalid value: {hour}"
                        ));
                    }
                }
            } else if pos == 2 {
                if value
                    .as_bytes()
                    .first()
                    .ok_or_else(|| "Invalid cron key: failed to parse cron weekday".to_string())?
                    == &b'*'
                {
                    return Ok(SimpleCron::Day { hour, minute });
                } else {
                    let day = value.parse::<u32>().map_err(|_| {
                        "Invalid cron key: failed to parse cron weekday".to_string()
                    })?;
                    if !(1..=7).contains(&hour) {
                        return Err(format!(
                            "Invalid cron key: failed to parse weekday, invalid value: {}, range is 1 (Monday) to 7 (Sunday).",
                            hour,
                        ));
                    }

                    return Ok(SimpleCron::Week { day, hour, minute });
                }
            }
        }

        Err("Invalid cron key: parse cron expression.".to_string())
    }
}

impl Default for SimpleCron {
    fn default() -> Self {
        SimpleCron::Hour { minute: 0 }
    }
}
