/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use ahash::AHashMap;
use utils::{config::Config, glob::GlobPattern};

use crate::{LookupStore, Stores, Value};

#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: AHashMap<String, Value<'static>>,
    globs: Vec<(GlobPattern, Value<'static>)>,
}

impl MemoryStore {
    pub fn get(&self, id: &str) -> Option<&Value<'static>> {
        self.entries.get(id).or_else(|| {
            self.globs
                .iter()
                .find_map(|(pattern, value)| pattern.matches(id).then_some(value))
        })
    }
}

pub fn parse_memory_stores(config: &mut Config, stores: &mut Stores) {
    let mut lookups = AHashMap::new();
    let mut errors = Vec::new();

    for (key, value) in &config.keys {
        if let Some(key) = key.strip_prefix("lookup.") {
            if let Some((id, key)) = key
                .split_once('.')
                .filter(|(id, key)| !id.is_empty() && !key.is_empty())
            {
                // Detect if the key is a glob pattern
                let mut last_ch = '\0';
                let mut has_escape = false;
                let mut is_glob = false;
                for ch in key.chars() {
                    match ch {
                        '\\' => {
                            has_escape = true;
                        }
                        '*' | '?' if last_ch != '\\' => {
                            is_glob = true;
                        }
                        _ => {}
                    }

                    last_ch = ch;
                }

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
                        Value::Text(value.to_string().into())
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
                let store = lookups
                    .entry(id.to_string())
                    .or_insert_with(MemoryStore::default);
                if is_glob {
                    store.globs.push((GlobPattern::compile(key, false), value));
                } else {
                    store.entries.insert(
                        if has_escape {
                            key.replace('\\', "")
                        } else {
                            key.to_string()
                        },
                        value,
                    );
                }
            } else {
                errors.push(key.to_string());
            }
        } else if !lookups.is_empty() {
            break;
        }
    }

    for error in errors {
        config.new_parse_error(error, "Invalid lookup key format");
    }

    for (id, store) in lookups {
        stores
            .lookup_stores
            .insert(id, LookupStore::Memory(store.into()));
    }
}
