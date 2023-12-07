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

use crate::{
    config::scripts::{RemoteList, SieveContext},
    core::to_store_value,
    USER_AGENT,
};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("lookup", plugin_id, 2);
}

pub fn register_map(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("lookup_map", plugin_id, 2);
}

pub fn register_remote(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("lookup_remote", plugin_id, 3);
}

pub fn register_local_domain(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("is_local_domain", plugin_id, 2);
}

pub fn exec(ctx: PluginContext<'_>) -> Variable {
    let lookup_id = ctx.arguments[0].to_string();
    let span = ctx.span;
    if let Some(lookup) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
        match &ctx.arguments[1] {
            Variable::Array(items) => {
                for item in items.iter() {
                    if !item.is_empty()
                        && ctx
                            .handle
                            .block_on(lookup.contains(to_store_value(item)))
                            .unwrap_or(false)
                    {
                        return true.into();
                    }
                }
                false
            }
            v if !v.is_empty() => ctx
                .handle
                .block_on(lookup.contains(to_store_value(v)))
                .unwrap_or(false),
            _ => false,
        }
    } else {
        tracing::warn!(
            parent: span,
            context = "sieve:lookup",
            event = "failed",
            reason = "Unknown lookup id",
            lookup_id = %lookup_id,
        );
        false
    }
    .into()
}

pub fn exec_map(ctx: PluginContext<'_>) -> Variable {
    let lookup_id = ctx.arguments[0].to_string();
    let items = match &ctx.arguments[1] {
        Variable::Array(l) => l.iter().map(to_store_value).collect(),
        v if !v.is_empty() => vec![to_store_value(v)],
        _ => vec![],
    };
    let span = ctx.span;

    if !lookup_id.is_empty() && !items.is_empty() {
        if let Some(lookup) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
            return ctx
                .handle
                .block_on(lookup.lookup(items))
                .unwrap_or_default();
        } else {
            tracing::warn!(
                parent: span,
                context = "sieve:lookup",
                event = "failed",
                reason = "Unknown lookup id",
                lookup_id = %lookup_id,
            );
        }
    }

    Variable::default()
}

pub fn exec_remote(ctx: PluginContext<'_>) -> Variable {
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

    match ctx
        .core
        .sieve
        .runtime
        .context()
        .remote_lists
        .lists
        .read()
        .get(resource.as_ref())
    {
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
        match arr.get(0) {
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

    // Lock remote list for writing
    let mut _lock = ctx.core.sieve.runtime.context().remote_lists.lists.write();
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

    let _enter = ctx.handle.enter();
    match ctx
        .handle
        .block_on(
            reqwest::Client::builder()
                .timeout(TIMEOUT)
                .user_agent(USER_AGENT)
                .build()
                .unwrap_or_default()
                .get(resource.as_ref())
                .send(),
        )
        .and_then(|r| {
            if r.status().is_success() {
                ctx.handle.block_on(r.bytes()).map(Ok)
            } else {
                Ok(Err(r))
            }
        }) {
        Ok(Ok(bytes)) => {
            let reader: Box<dyn std::io::Read> = if resource.ends_with(".gz") {
                Box::new(flate2::read::GzDecoder::new(&bytes[..]))
            } else {
                Box::new(&bytes[..])
            };

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
                            context = "sieve:lookup_remote",
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
                context = "sieve:lookup_remote",
                event = "fetch",
                resource = resource.as_ref(),
                num_entries = list.entries.len(),
            );

            // Update expiration
            list.expires = Instant::now() + expires;
            return list.entries.contains(item.as_ref()).into();
        }
        Ok(Err(response)) => {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:lookup_remote",
                event = "failed",
                resource = resource.as_ref(),
                status = %response.status(),
            );
        }
        Err(err) => {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:lookup_remote",
                event = "failed",
                resource = resource.as_ref(),
                reason = %err,
            );
        }
    }

    // Something went wrong, try again in one hour
    list.expires = Instant::now() + RETRY;
    false.into()
}

pub fn exec_local_domain(ctx: PluginContext<'_>) -> Variable {
    let directory_id = ctx.arguments[0].to_string();
    let domain = ctx.arguments[0].to_string();

    if !directory_id.is_empty() && !domain.is_empty() {
        if let Some(dir) = ctx.core.sieve.config.directories.get(directory_id.as_ref()) {
            return ctx
                .handle
                .block_on(dir.is_local_domain(domain.as_ref()))
                .unwrap_or_default()
                .into();
        } else {
            tracing::warn!(
                parent: ctx.span,
                context = "sieve:is_local_domain",
                event = "failed",
                reason = "Unknown directory",
                lookup_id = %directory_id,
            );
        }
    }

    Variable::default()
}
