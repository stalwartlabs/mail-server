/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use directory::Permission;
use sieve::{FunctionMap, compiler::Number, runtime::Variable};
use trc::{AiEvent, SecurityEvent};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("llm_prompt", plugin_id, 3);
}

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    #[cfg(feature = "enterprise")]
    if let (Variable::String(name), Variable::String(prompt)) =
        (&ctx.arguments[0], &ctx.arguments[1])
    {
        #[cfg(feature = "test_mode")]
        if name.as_ref() == "echo-test" {
            return Ok(prompt.to_string().into());
        }
        let temperature = ctx.arguments[2].to_number_checked().map(|n| match n {
            Number::Integer(n) => (n as f64).clamp(0.0, 1.0),
            Number::Float(n) => n.clamp(0.0, 1.0),
        });

        if let Some(ai_api) = ctx.server.core.enterprise.as_ref().and_then(|e| {
            if ctx.access_token.is_none_or(|token| {
                if token.has_permission(Permission::AiModelInteract) {
                    true
                } else {
                    trc::event!(
                        Security(SecurityEvent::Unauthorized),
                        AccountId = token.primary_id(),
                        Details = Permission::AiModelInteract.name(),
                        SpanId = ctx.session_id,
                    );
                    false
                }
            }) {
                if e.ai_apis.len() == 1 && name.is_empty() {
                    e.ai_apis.values().next()
                } else {
                    e.ai_apis.get(name.as_ref())
                }
            } else {
                None
            }
        }) {
            let time = Instant::now();
            match ai_api.send_request(prompt.as_ref(), temperature).await {
                Ok(response) => {
                    trc::event!(
                        Ai(AiEvent::LlmResponse),
                        Id = ai_api.id.clone(),
                        Value = prompt.to_string(),
                        Details = response.clone(),
                        Elapsed = time.elapsed(),
                        SpanId = ctx.session_id,
                    );

                    return Ok(response.into());
                }
                Err(err) => {
                    trc::error!(err.span_id(ctx.session_id));
                }
            }
        }
    }

    // SPDX-SnippetEnd

    Ok(false.into())
}
