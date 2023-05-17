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

use std::sync::Arc;

use ahash::AHashMap;

use super::{condition::ConfigCondition, ConfigContext, EnvelopeKey, IfBlock, IfThen};
use utils::config::{
    utils::{AsKey, ParseValues},
    Config,
};

pub trait ConfigIf {
    fn parse_if_block<T: Default + ParseValues>(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Option<IfBlock<T>>>;
}

impl ConfigIf for Config {
    fn parse_if_block<T: Default + ParseValues>(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Option<IfBlock<T>>> {
        let key = prefix.as_key();
        let prefix = prefix.as_prefix();

        let mut found_if = false;
        let mut found_else = "";
        let mut found_then = false;

        // Parse conditions
        let mut if_block = IfBlock::new(T::default());
        let mut last_array_pos = "";

        for item in self.keys.keys() {
            if let Some(suffix_) = item.strip_prefix(&prefix) {
                if let Some((array_pos, suffix)) = suffix_.split_once('.') {
                    let if_key = suffix.split_once('.').map(|(v, _)| v).unwrap_or(suffix);
                    if ["if", "any-of", "all-of", "none-of"].contains(&if_key) {
                        if array_pos != last_array_pos {
                            if !last_array_pos.is_empty() && !found_then && !T::is_multivalue() {
                                return Err(format!(
                                    "Missing 'then' in 'if' condition {} for property {:?}.",
                                    last_array_pos.parse().unwrap_or(0) + 1,
                                    key
                                ));
                            }

                            if_block.if_then.push(IfThen {
                                conditions: self.parse_condition(
                                    (key.as_str(), array_pos),
                                    ctx,
                                    available_keys,
                                )?,
                                then: T::default(),
                            });

                            found_then = false;
                            last_array_pos = array_pos;
                        }

                        found_if = true;
                    } else if if_key == "else" {
                        if found_else.is_empty() {
                            if found_if {
                                if_block.default = T::parse_values(
                                    (key.as_str(), suffix_.split_once(".else").unwrap().0, "else"),
                                    self,
                                )?;
                                found_else = array_pos;
                            } else {
                                return Err(format!(
                                    "Found 'else' before 'if' for property {key:?}.",
                                ));
                            }
                        } else if array_pos != found_else {
                            return Err(format!("Multiple 'else' found for property {key:?}."));
                        }
                    } else if if_key == "then" {
                        if found_else.is_empty() {
                            if array_pos == last_array_pos {
                                if !found_then {
                                    if_block.if_then.last_mut().unwrap().then = T::parse_values(
                                        (
                                            key.as_str(),
                                            suffix_.split_once(".then").unwrap().0,
                                            "then",
                                        ),
                                        self,
                                    )?;
                                    found_then = true;
                                }
                            } else {
                                return Err(format!(
                                    "Found 'then' without 'if' for property {key:?}.",
                                ));
                            }
                        } else {
                            return Err(format!(
                                "Found 'then' in 'else' block for property {key:?}.",
                            ));
                        }
                    }
                } else if !found_if {
                    // Found probably a multi-value, parse and return
                    if_block.default = T::parse_values(key.as_str(), self)?;
                    return Ok(Some(if_block));
                } else {
                    return Err(format!("Invalid property {item:?} found in 'if' block."));
                }
            } else if item == &key {
                // There is a single value, parse and return
                if_block.default = T::parse_values(key.as_str(), self)?;
                return Ok(Some(if_block));
            }
        }

        if !found_if {
            Ok(None)
        } else if !found_then && !T::is_multivalue() {
            Err(format!(
                "Missing 'then' in 'if' condition {} for property {:?}.",
                last_array_pos.parse().unwrap_or(0) + 1,
                key
            ))
        } else if found_else.is_empty() && !T::is_multivalue() {
            Err(format!("Missing 'else' for property {key:?}."))
        } else {
            Ok(Some(if_block))
        }
    }
}

impl<T: Default> IfBlock<T> {
    pub fn new(value: T) -> Self {
        Self {
            if_then: Vec::with_capacity(0),
            default: value,
        }
    }
}

impl<T: Default> IfBlock<Option<T>> {
    pub fn try_unwrap(self, key: &str) -> super::Result<IfBlock<T>> {
        let mut if_then = Vec::with_capacity(self.if_then.len());
        for if_clause in self.if_then {
            if_then.push(IfThen {
                conditions: if_clause.conditions,
                then: if_clause
                    .then
                    .ok_or_else(|| format!("Property {key:?} cannot contain null values."))?,
            });
        }

        Ok(IfBlock {
            if_then,
            default: self
                .default
                .ok_or_else(|| format!("Property {key:?} cannot contain null values."))?,
        })
    }
}

impl IfBlock<Option<String>> {
    pub fn map_if_block<T>(
        self,
        map: &AHashMap<String, Arc<T>>,
        key_name: impl AsKey,
        object_name: &str,
    ) -> super::Result<IfBlock<Option<Arc<T>>>> {
        let key_name = key_name.as_key();
        let mut if_then = Vec::with_capacity(self.if_then.len());
        for if_clause in self.if_then.into_iter() {
            if_then.push(IfThen {
                conditions: if_clause.conditions,
                then: Self::map_value(map, if_clause.then, object_name, &key_name)?,
            });
        }

        Ok(IfBlock {
            if_then,
            default: Self::map_value(map, self.default, object_name, &key_name)?,
        })
    }

    fn map_value<T>(
        map: &AHashMap<String, Arc<T>>,
        value: Option<String>,
        object_name: &str,
        key_name: &str,
    ) -> super::Result<Option<Arc<T>>> {
        if let Some(value) = value {
            if let Some(value) = map.get(&value) {
                Ok(Some(value.clone()))
            } else {
                Err(format!(
                    "Unable to find {object_name} {value:?} declared for {key_name:?}",
                ))
            }
        } else {
            Ok(None)
        }
    }
}

impl IfBlock<Vec<String>> {
    pub fn map_if_block<T>(
        self,
        map: &AHashMap<String, Arc<T>>,
        key_name: &str,
        object_name: &str,
    ) -> super::Result<IfBlock<Vec<Arc<T>>>> {
        let mut if_then = Vec::with_capacity(self.if_then.len());
        for if_clause in self.if_then.into_iter() {
            if_then.push(IfThen {
                conditions: if_clause.conditions,
                then: Self::map_value(map, if_clause.then, object_name, key_name)?,
            });
        }

        Ok(IfBlock {
            if_then,
            default: Self::map_value(map, self.default, object_name, key_name)?,
        })
    }

    fn map_value<T>(
        map: &AHashMap<String, Arc<T>>,
        values: Vec<String>,
        object_name: &str,
        key_name: &str,
    ) -> super::Result<Vec<Arc<T>>> {
        let mut result = Vec::with_capacity(values.len());
        for value in values {
            if let Some(value) = map.get(&value) {
                result.push(value.clone());
            } else {
                return Err(format!(
                    "Unable to find {object_name} {value:?} declared for {key_name:?}",
                ));
            }
        }
        Ok(result)
    }
}

impl<T> IfBlock<Vec<T>> {
    pub fn has_empty_list(&self) -> bool {
        self.default.is_empty() || self.if_then.iter().any(|v| v.then.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use utils::config::Config;

    use crate::config::{
        if_block::ConfigIf, Condition, ConditionMatch, Conditions, ConfigContext, EnvelopeKey,
        IfBlock, IfThen, StringMatch,
    };

    #[test]
    fn parse_if_blocks() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("smtp");
        file.push("config");
        file.push("if-blocks.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();

        // Create context and add some conditions
        let context = ConfigContext::new(&[]);
        let available_keys = vec![
            EnvelopeKey::Recipient,
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::Priority,
        ];

        assert_eq!(
            config
                .parse_if_block::<Option<Duration>>("durations", &context, &available_keys)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![Condition::Match {
                                key: EnvelopeKey::Sender,
                                value: ConditionMatch::String(StringMatch::Equal(
                                    "jdoe".to_string()
                                )),
                                not: false
                            }]
                        },
                        then: Duration::from_secs(5 * 86400).into()
                    },
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![
                                Condition::Match {
                                    key: EnvelopeKey::Priority,
                                    value: ConditionMatch::Int(-1),
                                    not: false
                                },
                                Condition::JumpIfTrue { positions: 1 },
                                Condition::Match {
                                    key: EnvelopeKey::Recipient,
                                    value: ConditionMatch::String(StringMatch::StartsWith(
                                        "jane".to_string()
                                    )),
                                    not: false
                                }
                            ]
                        },
                        then: Duration::from_secs(3600).into()
                    }
                ],
                default: None
            }
        );

        assert_eq!(
            config
                .parse_if_block::<Vec<String>>("string-list", &context, &available_keys)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![Condition::Match {
                                key: EnvelopeKey::Sender,
                                value: ConditionMatch::String(StringMatch::Equal(
                                    "jdoe".to_string()
                                )),
                                not: false
                            }]
                        },
                        then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                    },
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![
                                Condition::Match {
                                    key: EnvelopeKey::Priority,
                                    value: ConditionMatch::Int(-1),
                                    not: false
                                },
                                Condition::JumpIfTrue { positions: 1 },
                                Condition::Match {
                                    key: EnvelopeKey::Recipient,
                                    value: ConditionMatch::String(StringMatch::StartsWith(
                                        "jane".to_string()
                                    )),
                                    not: false
                                }
                            ]
                        },
                        then: vec!["Other-ID".to_string()]
                    }
                ],
                default: vec![]
            }
        );

        assert_eq!(
            config
                .parse_if_block::<Vec<String>>("string-list-bis", &context, &available_keys)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![Condition::Match {
                                key: EnvelopeKey::Sender,
                                value: ConditionMatch::String(StringMatch::Equal(
                                    "jdoe".to_string()
                                )),
                                not: false
                            }]
                        },
                        then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                    },
                    IfThen {
                        conditions: Conditions {
                            conditions: vec![
                                Condition::Match {
                                    key: EnvelopeKey::Priority,
                                    value: ConditionMatch::Int(-1),
                                    not: false
                                },
                                Condition::JumpIfTrue { positions: 1 },
                                Condition::Match {
                                    key: EnvelopeKey::Recipient,
                                    value: ConditionMatch::String(StringMatch::StartsWith(
                                        "jane".to_string()
                                    )),
                                    not: false
                                }
                            ]
                        },
                        then: vec![]
                    }
                ],
                default: vec!["ID-Bis".to_string()]
            }
        );

        assert_eq!(
            config
                .parse_if_block::<String>("single-value", &context, &available_keys)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![],
                default: "hello world".to_string()
            }
        );

        for bad_rule in [
            "bad-multi-value",
            "bad-if-without-then",
            "bad-if-without-else",
            "bad-multiple-else",
        ] {
            if let Ok(value) = config.parse_if_block::<u32>(bad_rule, &context, &available_keys) {
                panic!("Condition {bad_rule:?} had unexpected result {value:?}");
            }
        }
    }
}
