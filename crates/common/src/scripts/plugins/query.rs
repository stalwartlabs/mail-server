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
 * in the LICENSE file at the top-level store of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::cmp::Ordering;

use crate::scripts::{into_sieve_value, to_store_value};
use sieve::{runtime::Variable, FunctionMap};
use store::{Rows, Value};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("query", plugin_id, 3);
}

pub async fn exec(ctx: PluginContext<'_>) -> Variable {
    let span = ctx.span;

    // Obtain store name
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    };

    let store = if let Some(store) = store {
        store
    } else {
        tracing::warn!(
            parent: span,
            context = "sieve:query",
            event = "failed",
            reason = "Unknown store",
            store = ctx.arguments[0].to_string().as_ref(),
        );
        return false.into();
    };

    // Obtain query string
    let query = ctx.arguments[1].to_string();
    if query.is_empty() {
        tracing::warn!(
            parent: span,
            context = "sieve:query",
            event = "invalid",
            reason = "Empty query string",
        );
        return false.into();
    }

    // Obtain arguments
    let arguments = match &ctx.arguments[2] {
        Variable::Array(l) => l.iter().map(to_store_value).collect(),
        v => vec![to_store_value(v)],
    };

    // Run query
    if query
        .as_bytes()
        .get(..6)
        .map_or(false, |q| q.eq_ignore_ascii_case(b"SELECT"))
    {
        if let Ok(mut rows) = store.query::<Rows>(&query, arguments).await {
            match rows.rows.len().cmp(&1) {
                Ordering::Equal => {
                    let mut row = rows.rows.pop().unwrap().values;
                    match row.len().cmp(&1) {
                        Ordering::Equal if !matches!(row.first(), Some(Value::Null)) => {
                            row.pop().map(into_sieve_value).unwrap()
                        }
                        Ordering::Less => Variable::default(),
                        _ => Variable::Array(
                            row.into_iter()
                                .map(into_sieve_value)
                                .collect::<Vec<_>>()
                                .into(),
                        ),
                    }
                }
                Ordering::Less => Variable::default(),
                Ordering::Greater => rows
                    .rows
                    .into_iter()
                    .map(|r| {
                        Variable::Array(
                            r.values
                                .into_iter()
                                .map(into_sieve_value)
                                .collect::<Vec<_>>()
                                .into(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into(),
            }
        } else {
            false.into()
        }
    } else {
        store.query::<usize>(&query, arguments).await.is_ok().into()
    }
}
