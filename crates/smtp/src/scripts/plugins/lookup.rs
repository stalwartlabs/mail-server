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

use sieve::{runtime::Variable, FunctionMap};

use crate::config::scripts::SieveContext;

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap<SieveContext>) {
    fnc_map.set_external_function("lookup", plugin_id, 2);
}

pub fn exec(ctx: PluginContext<'_>) -> Variable<'static> {
    let lookup_id = ctx.arguments[0].to_cow();
    let item = ctx.arguments[1].to_cow();
    let span = ctx.span;

    if !lookup_id.is_empty() && !item.is_empty() {
        if let Some(lookup) = ctx.core.sieve.lookup.get(lookup_id.as_ref()) {
            return ctx
                .handle
                .block_on(lookup.contains(item.as_ref()))
                .unwrap_or(false)
                .into();
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

    false.into()
}
