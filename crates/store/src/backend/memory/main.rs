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

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use crate::Value;

use super::{glob::GlobPattern, LookupList, LookupMap, MatchType, MemoryStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupType {
    List,
    Glob,
    Regex,
    Map,
}

#[derive(Debug, Clone)]
pub struct LookupFormat {
    pub lookup_type: LookupType,
    pub comment: Option<String>,
    pub separator: Option<String>,
}

impl MemoryStore {
    pub async fn open(config: &Config, prefix: impl AsKey) -> crate::Result<Self> {
        let prefix = prefix.as_key();

        let lookup_type = config.property_require::<LookupType>((&prefix, "format"))?;
        let format = LookupFormat {
            lookup_type,
            comment: config.value((&prefix, "comment")).map(|s| s.to_string()),
            separator: config.value((&prefix, "separator")).map(|s| s.to_string()),
        };

        Ok(match lookup_type {
            LookupType::Map => {
                MemoryStore::Map(parse_lookup_list(config, (&prefix, "values"), format)?)
            }
            _ => MemoryStore::List(parse_lookup_list(config, (&prefix, "values"), format)?),
        })
    }
}

fn parse_lookup_list<K: AsKey, T: InsertLine>(
    config: &Config,
    key: K,
    format: LookupFormat,
) -> utils::config::Result<T> {
    let mut list = T::default();
    let mut last_failed = false;
    for (_, mut value) in config.values(key.clone()) {
        if let Some(new_value) = value.strip_prefix("fallback+") {
            if last_failed {
                value = new_value;
            } else {
                continue;
            }
        }
        last_failed = false;

        if value.starts_with("https://") || value.starts_with("http://") {
            match tokio::task::block_in_place(|| {
                reqwest::blocking::get(value).and_then(|r| {
                    if r.status().is_success() {
                        r.bytes().map(Ok)
                    } else {
                        Ok(Err(r))
                    }
                })
            }) {
                Ok(Ok(bytes)) => {
                    match list.insert_lines(&*bytes, &format, value.ends_with(".gz")) {
                        Ok(_) => continue,
                        Err(err) => {
                            tracing::warn!(
                                "Failed to read list {key:?} from {value:?}: {err}",
                                key = key.as_key(),
                                value = value,
                                err = err
                            );
                        }
                    }
                }
                Ok(Err(response)) => {
                    tracing::warn!(
                        "Failed to fetch list {key:?} from {value:?}: Status {status}",
                        key = key.as_key(),
                        value = value,
                        status = response.status()
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to fetch list {key:?} from {value:?}: {err}",
                        key = key.as_key(),
                        value = value,
                        err = err
                    );
                }
            }
            last_failed = true;
        } else if let Some(path) = value.strip_prefix("file://") {
            list.insert_lines(
                File::open(path).map_err(|err| {
                    format!(
                        "Failed to read file {path:?} for list {}: {err}",
                        key.as_key()
                    )
                })?,
                &format,
                value.ends_with(".gz"),
            )
            .map_err(|err| {
                format!(
                    "Failed to read file {path:?} for list {}: {err}",
                    key.as_key()
                )
            })?;
        } else {
            list.insert(value.to_string(), &format);
        }
    }
    Ok(list)
}

pub trait InsertLine: Default {
    fn insert(&mut self, entry: String, format: &LookupFormat);
    fn insert_lines<R: Sized + std::io::Read>(
        &mut self,
        reader: R,
        format: &LookupFormat,
        decompress: bool,
    ) -> Result<(), std::io::Error> {
        let reader: Box<dyn std::io::Read> = if decompress {
            Box::new(flate2::read::GzDecoder::new(reader))
        } else {
            Box::new(reader)
        };

        for line in BufReader::new(reader).lines() {
            let line_ = line?;
            let line = line_.trim();
            if !line.is_empty()
                && format
                    .comment
                    .as_ref()
                    .map_or(true, |c| !line.starts_with(c))
            {
                self.insert(line.to_string(), format);
            }
        }
        Ok(())
    }
}

impl InsertLine for LookupList {
    fn insert(&mut self, entry: String, format: &LookupFormat) {
        match format.lookup_type {
            LookupType::List => {
                self.set.insert(entry);
            }
            LookupType::Glob => {
                let n_wildcards = entry
                    .as_bytes()
                    .iter()
                    .filter(|&&ch| ch == b'*' || ch == b'?')
                    .count();
                if n_wildcards > 0 {
                    if n_wildcards == 1 {
                        if let Some(s) = entry.strip_prefix('*') {
                            if !s.is_empty() {
                                self.matches.push(MatchType::EndsWith(s.to_string()));
                            }
                            return;
                        } else if let Some(s) = entry.strip_suffix('*') {
                            if !s.is_empty() {
                                self.matches.push(MatchType::StartsWith(s.to_string()));
                            }
                            return;
                        }
                    }
                    self.matches
                        .push(MatchType::Glob(GlobPattern::compile(&entry, false)));
                } else {
                    self.set.insert(entry);
                }
            }
            LookupType::Regex => match regex::Regex::new(&entry) {
                Ok(regex) => {
                    self.matches.push(MatchType::Regex(regex));
                }
                Err(err) => {
                    tracing::warn!("Invalid regular expression {:?}: {}", entry, err);
                }
            },
            LookupType::Map => unreachable!(),
        }
    }
}

impl InsertLine for LookupMap {
    fn insert(&mut self, entry: String, format: &LookupFormat) {
        let (key, value) = entry
            .split_once(format.separator.as_deref().unwrap_or(" "))
            .unwrap_or((entry.as_str(), ""));
        let key = key.trim();
        if key.is_empty() {
            return;
        } else if value.is_empty() {
            self.insert(key.to_string(), Value::Null);
            return;
        }
        let mut has_digit = false;
        let mut has_dots = false;
        let mut has_other = false;

        for (pos, ch) in value.bytes().enumerate() {
            if ch.is_ascii_digit() {
                has_digit = true;
            } else if ch == b'.' {
                has_dots = true;
            } else if pos > 0 || ch != b'-' {
                has_other = true;
            }
        }

        let value = if has_other || !has_digit {
            Value::Text(value.to_string().into())
        } else if has_dots {
            value
                .parse()
                .map(Value::Float)
                .unwrap_or_else(|_| Value::Text(value.to_string().into()))
        } else {
            value
                .parse()
                .map(Value::Integer)
                .unwrap_or_else(|_| Value::Text(value.to_string().into()))
        };

        self.insert(key.to_string(), value);
    }
}

impl Default for LookupFormat {
    fn default() -> Self {
        Self {
            lookup_type: LookupType::Glob,
            comment: Default::default(),
            separator: Default::default(),
        }
    }
}

impl ParseValue for LookupType {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
        match value {
            "list" => Ok(LookupType::List),
            "glob" => Ok(LookupType::Glob),
            "regex" => Ok(LookupType::Regex),
            "map" => Ok(LookupType::Map),
            _ => Err(format!(
                "Invalid value for lookup type {key:?}: {value:?}",
                key = key.as_key(),
                value = value
            )),
        }
    }
}
