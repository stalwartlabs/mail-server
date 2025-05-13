/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use reqwest::redirect::Policy;
use sieve::{runtime::Variable, FunctionMap};

use super::PluginContext;

pub fn register_header(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("http_header", plugin_id, 4);
}

pub async fn exec_header(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let url = ctx.arguments[0].to_string();
    let header = ctx.arguments[1].to_string();
    let agent = ctx.arguments[2].to_string();
    let timeout = ctx.arguments[3].to_string().parse::<u64>().unwrap_or(5000);

    #[cfg(feature = "test_mode")]
    if url.contains("redirect.") {
        return Ok(Variable::from(url.split_once("/?").unwrap().1.to_string()));
    }

    reqwest::Client::builder()
        .user_agent(agent.as_ref())
        .timeout(Duration::from_millis(timeout))
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .details("Failed to build request")
        })?
        .get(url.as_ref())
        .send()
        .await
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .details("Failed to send request")
        })
        .map(|response| {
            response
                .headers()
                .get(header.as_ref())
                .and_then(|h| h.to_str().ok())
                .map(|h| Variable::from(h.to_string()))
                .unwrap_or_default()
        })
}
