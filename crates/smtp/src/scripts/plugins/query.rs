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

use directory::QueryColumn;
use sieve::{runtime::Variable, Compiler, Input, PluginArgument, SetVariable};
use smtp_proto::IntoString;

use super::PluginContext;

pub fn register(plugin_id: u32, compiler: &mut Compiler) {
    compiler
        .register_plugin("query")
        .with_id(plugin_id)
        .with_tagged_string_argument("use")
        .with_tagged_variable_array_argument("set")
        .with_string_argument()
        .with_string_array_argument();
}

pub fn exec(ctx: PluginContext<'_>) -> Input {
    let span = ctx.span;
    let mut arguments = ctx.arguments.into_iter();
    let query = arguments
        .next()
        .and_then(|a| a.unwrap_string())
        .unwrap_or_default();

    if query.is_empty() {
        tracing::warn!(
            parent: span,
            context = "sieve:query",
            event = "invalid",
            reason = "Empty query string",
        );
        return false.into();
    }

    let parameters = arguments
        .next()
        .and_then(|a| a.unwrap_string_array())
        .unwrap_or_default();
    let mut directory = None;
    let mut set_variables = vec![];

    while let Some(arg) = arguments.next() {
        if let PluginArgument::Tag(tag_id) = arg {
            match tag_id {
                0 => {
                    let name = arguments
                        .next()
                        .and_then(|a| a.unwrap_string())
                        .unwrap_or_default();
                    if let Some(directory_) = ctx.core.sieve.config.directories.get(&name) {
                        directory = Some(directory_);
                    } else {
                        tracing::warn!(
                            parent: span,
                            context = "sieve:query",
                            event = "failed",
                            reason = "Unknown directory",
                            directory = %name,
                        );
                        return false.into();
                    }
                }
                1 => {
                    set_variables = arguments
                        .next()
                        .and_then(|a| a.unwrap_variable_array())
                        .unwrap_or_default();
                }
                _ => {}
            }
        }
    }

    let directory = if let Some(directory) = directory {
        directory
    } else if let Some(directory) = ctx.core.sieve.config.directories.values().next() {
        directory
    } else {
        tracing::warn!(
            parent: span,
            context = "sieve:query",
            event = "failed",
            reason = "No directory configured",
        );
        return false.into();
    };

    if !set_variables.is_empty() {
        if let Ok(result) = ctx.handle.block_on(directory.query(
            &query,
            &parameters.iter().map(String::as_str).collect::<Vec<_>>(),
        )) {
            let mut list = vec![];
            for (name, value) in set_variables.into_iter().zip(result) {
                list.push(SetVariable {
                    name,
                    value: match value {
                        QueryColumn::Integer(v) => Variable::Integer(v),
                        QueryColumn::Bool(v) => Variable::Integer(i64::from(v)),
                        QueryColumn::Float(v) => Variable::Float(v),
                        QueryColumn::Text(v) => Variable::String(v),
                        QueryColumn::Blob(v) => Variable::String(v.into_string()),
                        QueryColumn::Null => Variable::StringRef(""),
                    },
                });
            }
            Input::variables(list)
        } else {
            false.into()
        }
    } else {
        let result = ctx.handle.block_on(directory.lookup(
            &query,
            &parameters.iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        if query
            .as_bytes()
            .get(..6)
            .map_or(false, |q| q.eq_ignore_ascii_case(b"SELECT"))
        {
            result.unwrap_or(false).into()
        } else {
            result.is_ok().into()
        }
    }
}
