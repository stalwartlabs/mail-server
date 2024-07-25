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

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let mut arguments = ctx.arguments.into_iter();

    tokio::task::spawn_blocking(move || {
        let command = arguments
            .next()
            .map(|a| a.to_string().into_owned())
            .unwrap_or_default();

        match Command::new(&command)
            .args(
                arguments
                    .next()
                    .map(|a| a.into_string_array())
                    .unwrap_or_default(),
            )
            .output()
        {
            Ok(result) => Ok(result.status.success()),
            Err(err) => Err(trc::SieveEvent::RuntimeError
                .ctx(trc::Key::Path, command)
                .reason(err)
                .details("Failed to execute command")),
        }
    })
    .await
    .map_err(|err| {
        trc::EventType::Server(trc::ServerEvent::ThreadError)
            .reason(err)
            .caused_by(trc::location!())
            .details("Join Error")
    })?
    .map(Into::into)
}
