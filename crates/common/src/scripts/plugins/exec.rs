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

use std::process::Command;

use sieve::{runtime::Variable, FunctionMap};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("exec", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> Variable {
    let span = ctx.span.clone();
    let mut arguments = ctx.arguments.into_iter();

    tokio::task::spawn_blocking(move || {
        match Command::new(
            arguments
                .next()
                .map(|a| a.to_string().into_owned())
                .unwrap_or_default(),
        )
        .args(
            arguments
                .next()
                .map(|a| a.into_string_array())
                .unwrap_or_default(),
        )
        .output()
        {
            Ok(result) => result.status.success(),
            Err(err) => {
                tracing::warn!(
                    parent: span,
                    context = "sieve",
                    event = "execute-failed",
                    reason = %err,
                );
                false
            }
        }
    })
    .await
    .unwrap_or_default()
    .into()
}
