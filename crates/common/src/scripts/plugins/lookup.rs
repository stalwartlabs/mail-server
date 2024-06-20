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

use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    time::{Duration, Instant},
};

use mail_auth::flate2;
use sieve::{runtime::Variable, FunctionMap};
use store::{Deserialize, Value};

use crate::{config::scripts::RemoteList, scripts::into_sieve_value, USER_AGENT};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_exists", plugin_id, 2);
}

pub fn register_get(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_get", plugin_id, 2);
}

pub fn register_set(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_set", plugin_id, 4);
}

pub fn register_remote(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_exists_http", plugin_id, 3);
}

pub fn register_local_domain(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("is_local_domain", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> Variable {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };

    if let Some(store) = store {
        match &ctx.arguments[1] {
            Variable::Array(items) => {
                for item in items.iter() {
                    if !item.is_empty()
                        && store
                            .key_exists(item.to_string().into_owned().into_bytes())
                            .await
                            .unwrap_or(false)
                    {
                        return true.into();
                    }
                }
                false
            }
            v if !v.is_empty() => store
                .key_exists(v.to_string().into_owned().into_bytes())
                .await
                .unwrap_or(false),
            _ => false,
        }
    } else {
        tracing::debug!(
            parent: ctx.span,
            context = "sieve:lookup",
            event = "failed",
            reason = "Unknown lookup id",
            lookup_id = ctx.arguments[0].to_string().as_ref(),
        );
        false
    }
    .into()
}

pub async fn exec_get(ctx: PluginContext<'_>) -> Variable {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };

    if let Some(store) = store {
        store
            .key_get::<VariableWrapper>(ctx.arguments[1].to_string().into_owned().into_bytes())
            .await
            .unwrap_or_default()
            .map(|v| v.into_inner())
            .unwrap_or_default()
    } else {
        tracing::debug!(
            parent: ctx.span,
            context = "sieve:key_get",
            event = "failed",
            reason = "Unknown store or lookup id",
            lookup_id = ctx.arguments[0].to_string().as_ref(),
        );
        Variable::default()
    }
}

pub async fn exec_set(ctx: PluginContext<'_>) -> Variable {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };

    if let Some(store) = store {
        let expires = match &ctx.arguments[3] {
            Variable::Integer(v) => Some(*v as u64),
            Variable::Float(v) => Some(*v as u64),
            _ => None,
        };

        store
            .key_set(
                ctx.arguments[1].to_string().into_owned().into_bytes(),
                if !ctx.arguments[2].is_empty() {
                    bincode::serialize(&ctx.arguments[2]).unwrap_or_default()
                } else {
                    vec![]
                },
                expires,
            )
            .await
            .is_ok()
            .into()
    } else {
        tracing::warn!(
            parent: ctx.span,
            context = "sieve:key_set",
            event = "failed",
            reason = "Unknown store id",
            store_id = ctx.arguments[0].to_string().as_ref(),
        );
        Variable::default()
    }
}

pub async fn exec_remote(ctx: PluginContext<'_>) -> Variable {
    let resource = ctx.arguments[0].to_string();
    let item = ctx.arguments[1].to_string();

    #[cfg(feature = "test_mode")]
    {
        if (resource.contains("open") && item.contains("open"))
            || (resource.contains("tank") && item.contains("tank"))
        {
            return true.into();
        }
    }

    if resource.is_empty() || item.is_empty() {
        return false.into();
    }

    const TIMEOUT: Duration = Duration::from_secs(45);
    const RETRY: Duration = Duration::from_secs(3600);
    const MAX_ENTRY_SIZE: usize = 256;
    const MAX_ENTRIES: usize = 100000;

    match ctx.cache.remote_lists.read().get(resource.as_ref()) {
        Some(remote_list) if remote_list.expires < Instant::now() => {
            return remote_list.entries.contains(item.as_ref()).into()
        }
        _ => {}
    }

    enum Format {
        List,
        Csv {
            column: u32,
            separator: char,
            skip_first: bool,
        },
    }

    // Obtain parameters
    let mut format = Format::List;
    let mut expires = Duration::from_secs(12 * 3600);

    if let Some(arr) = ctx.arguments[2].as_array() {
        // Obtain expiration
        match arr.first() {
            Some(Variable::Integer(v)) if *v > 0 => {
                expires = Duration::from_secs(*v as u64);
            }
            Some(Variable::Float(v)) if *v > 0.0 => {
                expires = Duration::from_secs(*v as u64);
            }
            _ => (),
        }

        // Obtain list type
        if matches!(arr.get(1), Some(Variable::String(list_type)) if list_type.eq_ignore_ascii_case("csv"))
        {
            format = Format::Csv {
                column: arr.get(2).map(|v| v.to_integer()).unwrap_or_default() as u32,
                separator: arr
                    .get(3)
                    .and_then(|v| v.to_string().chars().next())
                    .unwrap_or(','),
                skip_first: arr.get(4).map_or(false, |v| v.to_bool()),
            };
        }
    }

    match reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
        .get(resource.as_ref())
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.bytes().await {
                Ok(bytes) => {
                    let reader: Box<dyn std::io::Read> = if resource.ends_with(".gz") {
                        Box::new(flate2::read::GzDecoder::new(&bytes[..]))
                    } else {
                        Box::new(&bytes[..])
                    };

                    // Lock remote list for writing
                    let mut _lock = ctx.cache.remote_lists.write();
                    let list = _lock
                        .entry(resource.to_string())
                        .or_insert_with(|| RemoteList {
                            entries: HashSet::new(),
                            expires: Instant::now(),
                        });

                    // Make sure that the list is still expired
                    if list.expires > Instant::now() {
                        return list.entries.contains(item.as_ref()).into();
                    }

                    for (pos, line) in BufReader::new(reader).lines().enumerate() {
                        match line {
                            Ok(line_) => {
                                // Clear list once the first entry has been successfully fetched, decompressed and UTF8-decoded
                                if pos == 0 {
                                    list.entries.clear();
                                }

                                match &format {
                                    Format::List => {
                                        let line = line_.trim();
                                        if !line.is_empty() {
                                            list.entries.insert(line.to_string());
                                        }
                                    }
                                    Format::Csv {
                                        column,
                                        separator,
                                        skip_first,
                                    } if pos > 0 || !*skip_first => {
                                        let mut in_quote = false;
                                        let mut col_num = 0;
                                        let mut entry = String::new();

                                        for ch in line_.chars() {
                                            if ch != '"' {
                                                if ch == *separator && !in_quote {
                                                    if col_num == *column {
                                                        break;
                                                    } else {
                                                        col_num += 1;
                                                    }
                                                } else if col_num == *column {
                                                    entry.push(ch);
                                                    if entry.len() > MAX_ENTRY_SIZE {
                                                        break;
                                                    }
                                                }
                                            } else {
                                                in_quote = !in_quote;
                                            }
                                        }

                                        if !entry.is_empty() {
                                            list.entries.insert(entry);
                                        }
                                    }
                                    _ => (),
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    parent: ctx.span,
                                    context = "sieve:key_exists_http",
                                    event = "failed",
                                    resource = resource.as_ref(),
                                    reason = %err,
                                );
                                break;
                            }
                        }

                        if list.entries.len() == MAX_ENTRIES {
                            break;
                        }
                    }

                    tracing::debug!(
                        parent: ctx.span,
                        context = "sieve:key_exists_http",
                        event = "fetch",
                        resource = resource.as_ref(),
                        num_entries = list.entries.len(),
                    );

                    // Update expiration
                    list.expires = Instant::now() + expires;
                    return list.entries.contains(item.as_ref()).into();
                }
                Err(err) => {
                    tracing::warn!(
                        parent: ctx.span,
                        context = "sieve:key_exists_http",
                        event = "failed",
                        resource = resource.as_ref(),
                        reason = %err,
                    );
                }
            }
        }
        Ok(response) => {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:key_exists_http",
                event = "failed",
                resource = resource.as_ref(),
                status = %response.status(),
            );
        }
        Err(err) => {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:key_exists_http",
                event = "failed",
                resource = resource.as_ref(),
                reason = %err,
            );
        }
    }

    // Something went wrong, try again in one hour
    let mut _lock = ctx.cache.remote_lists.write();
    let list = _lock
        .entry(resource.to_string())
        .or_insert_with(|| RemoteList {
            entries: HashSet::new(),
            expires: Instant::now(),
        });
    if list.expires > Instant::now() {
        list.entries.contains(item.as_ref()).into()
    } else {
        list.expires = Instant::now() + RETRY;
        false.into()
    }
}

pub async fn exec_local_domain(ctx: PluginContext<'_>) -> Variable {
    let domain = ctx.arguments[0].to_string();

    if !domain.is_empty() {
        let directory = match &ctx.arguments[0] {
            Variable::String(v) if !v.is_empty() => ctx.core.storage.directories.get(v.as_ref()),
            _ => Some(&ctx.core.storage.directory),
        };

        if let Some(directory) = directory {
            return directory
                .is_local_domain(domain.as_ref())
                .await
                .unwrap_or_default()
                .into();
        } else {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:is_local_domain",
                event = "failed",
                reason = "Unknown directory",
                lookup_id = ctx.arguments[0].to_string().as_ref(),
            );
        }
    }

    Variable::default()
}

#[derive(Debug, PartialEq, Eq)]
pub struct VariableWrapper(Variable);

impl Deserialize for VariableWrapper {
    fn deserialize(bytes: &[u8]) -> store::Result<Self> {
        Ok(VariableWrapper(
            bincode::deserialize::<Variable>(bytes).unwrap_or_else(|_| {
                Variable::String(String::from_utf8_lossy(bytes).into_owned().into())
            }),
        ))
    }
}

impl From<i64> for VariableWrapper {
    fn from(value: i64) -> Self {
        VariableWrapper(value.into())
    }
}

impl VariableWrapper {
    pub fn into_inner(self) -> Variable {
        self.0
    }
}

impl From<Value<'static>> for VariableWrapper {
    fn from(value: Value<'static>) -> Self {
        VariableWrapper(into_sieve_value(value))
    }
}
