/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use super::{Mode, MxPattern, Policy};

impl Policy {
    pub fn parse(mut data: &str, id: String) -> Result<Policy, String> {
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

