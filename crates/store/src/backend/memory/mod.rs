/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::hash_map::Entry;

use ahash::AHashMap;
use utils::{config::Config, glob::GlobMap};

use crate::{InMemoryStore, Stores, Value};

pub type StaticMemoryStore = GlobMap<Value<'static>>;

impl Stores {
    pub fn parse_static_stores(&mut self, config: &mut Config, is_reload: bool) {
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
                    .or_insert_with(StaticMemoryStore::default)
                    .insert(key, value);
            } else {
                errors.push(key.to_string());
            }
        }

        for error in errors {
            config.new_parse_error(error, "Invalid lookup key format");
        }

        for (id, store) in lookups {
            match self.in_memory_stores.entry(id) {
                Entry::Vacant(entry) => {
                    entry.insert(InMemoryStore::Static(store.into()));
                }
                Entry::Occupied(e) if !is_reload => {
                    config.new_build_error(
                        ("lookup", e.key().as_str()),
                        "An in-memory store with this id already exists",
                    );
                }
                _ => {}
            }
        }
    }
}
