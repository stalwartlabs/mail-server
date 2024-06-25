/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
