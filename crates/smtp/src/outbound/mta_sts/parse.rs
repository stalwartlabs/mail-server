/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::{Mode, MxPattern, Policy};

pub trait ParsePolicy {
    fn parse(data: &str, id: String) -> Result<Self, String>
    where
        Self: Sized;
}

impl ParsePolicy for Policy {
    fn parse(mut data: &str, id: String) -> Result<Policy, String> {
        let mut mode = Mode::None;
        let mut max_age: u64 = 86400;
        let mut mx = Vec::new();

        while !data.is_empty() {
            if let Some((key, next_data)) = data.split_once(':') {
                let value = if let Some((value, next_data)) = next_data.split_once('\n') {
                    data = next_data;
                    value.trim()
                } else {
                    data = "";
                    next_data.trim()
                };
                match key.trim() {
                    "mx" => {
                        if let Some(suffix) = value.strip_prefix("*.") {
                            if !suffix.is_empty() {
                                mx.push(MxPattern::StartsWith(suffix.to_lowercase()));
                            }
                        } else if !value.is_empty() {
                            mx.push(MxPattern::Equals(value.to_lowercase()));
                        }
                    }
                    "max_age" => {
                        if let Ok(value) = value.parse() {
                            max_age = value;
                        }
                    }
                    "mode" => {
                        mode = match value {
                            "enforce" => Mode::Enforce,
                            "testing" => Mode::Testing,
                            "none" => Mode::None,
                            _ => return Err(format!("Unsupported mode {value:?}.")),
                        };
                    }
                    "version" => {
                        if !value.eq_ignore_ascii_case("STSv1") {
                            return Err(format!("Unsupported version {value:?}."));
                        }
                    }
                    _ => (),
                }
            } else {
                break;
            }
        }

        if !mx.is_empty() {
            Ok(Policy {
                id,
                mode,
                mx,
                max_age,
            })
        } else {
            Err("No 'mx' entries found.".to_string())
        }
    }
}
