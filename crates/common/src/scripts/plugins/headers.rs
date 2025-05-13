/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{runtime::Variable, FunctionMap};

use crate::scripts::ScriptModification;

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("add_header", plugin_id, 2);
}

pub fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    Ok(if let (Variable::String(name), Variable::String(value)) =
        (&ctx.arguments[0], &ctx.arguments[1])
    {
        ctx.modifications.push(ScriptModification::AddHeader {
            name: name.clone(),
            value: value.clone(),
        });
        true
    } else {
        false
    }
    .into())
}
