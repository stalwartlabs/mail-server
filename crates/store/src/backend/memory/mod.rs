/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use utils::{config::Config, glob::GlobMap};

use crate::{LookupStore, Stores, Value};

pub type MemoryStore = GlobMap<Value<'static>>;

impl Stores {
    pub fn parse_memory_stores(&mut self, config: &mut Config) {
        let mut lookups = AHashMap::new();
        let mut errors = Vec::new();

        for (key, value) in config.iterate_prefix("lookup") {
            if let Some((id, key)) = key
                .split_once('.')
                .filter(|(id, key)| !id.is_empty() && !key.is_empty())
            {
                // Detect value type
                let value = if !value.is_empty() {
                    let mut has_integers = false;
                    let mut has_floats = false;
                    let mut has_others = false;

                    for (pos, ch) in value.as_bytes().iter().enumerate() {
                        match ch {
                            b'.' if !has_floats && has_integers => {
                                has_floats = true;
                            }
                            b'0'..=b'9' => {
                                has_integers = true;
                            }
                            b'-' if pos == 0 && value.len() > 1 => {}
                            _ => {
                                has_others = true;
                            }
                        }
                    }

                    if has_others {
                        if value == "true" {
                            Value::Integer(1.into())
                        } else if value == "false" {
                            Value::Integer(0.into())
                        } else {
                            Value::Text(value.to_string().into())
                        }
                    } else if has_floats {
                        value
                            .parse()
                            .map(Value::Float)
                            .unwrap_or_else(|_| Value::Text(value.to_string().into()))
                    } else {
                        value
                            .parse()
                            .map(Value::Integer)
                            .unwrap_or_else(|_| Value::Text(value.to_string().into()))
                    }
                } else {
                    Value::Text("".into())
                };

                // Add entry
                lookups
                    .entry(id.to_string())
                    .or_insert_with(MemoryStore::default)
                    .insert(key, value);
            } else {
                errors.push(key.to_string());
            }
        }

        for error in errors {
            config.new_parse_error(error, "Invalid lookup key format");
        }

        for (id, store) in lookups {
            self.lookup_stores
                .insert(id, LookupStore::Memory(store.into()));
        }
    }
}
