/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::session::MTAHook;

use super::{Request, Response};

pub(super) async fn send_mta_hook_request(
    mta_hook: &MTAHook,
    request: Request,
) -> Result<Response, String> {
    let response = reqwest::Client::builder()
        .timeout(mta_hook.timeout)
        .danger_accept_invalid_certs(mta_hook.tls_allow_invalid_certs)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(&mta_hook.url)
        .headers(mta_hook.headers.clone())
        .body(
            serde_json::to_string(&request)
                .map_err(|err| format!("Failed to serialize Hook request: {}", err))?,
        )
        .send()
        .await
        .map_err(|err| format!("Hook request failed: {err}"))?;

    if response.status().is_success() {
        if response
            .content_length()
            .map_or(false, |len| len as usize > mta_hook.max_response_size)
        {
            return Err(format!(
                "Hook response too large ({} bytes)",
                response.content_length().unwrap()
            ));
        }

        // TODO: Stream response body to limit response size
        serde_json::from_slice(
            response
                .bytes()
                .await
                .map_err(|err| format!("Failed to parse Hook response: {}", err))?
                .as_ref(),
        )
        .map_err(|err| format!("Failed to parse Hook response: {}", err))
    } else {
        Err(format!(
            "Hook request failed with code {}: {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}
