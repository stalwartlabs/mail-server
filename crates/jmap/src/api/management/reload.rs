/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    services::housekeeper::Event,
    JMAP,
};

impl JMAP {
    pub async fn handle_manage_reload(&self, req: &HttpRequest, path: Vec<&str>) -> HttpResponse {
        match (path.get(1).copied(), req.method()) {
            (Some("lookup"), &Method::GET) => {
                match self.core.reload_lookups().await {
                    Ok(result) => {
                        // Update core
                        if let Some(core) = result.new_core {
                            self.shared_core.store(core.into());
                        }

                        JsonResponse::new(json!({
                            "data": result.config,
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (Some("certificate"), &Method::GET) => match self.core.reload_certificates().await {
                Ok(result) => JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response(),
                Err(err) => err.into_http_response(),
            },
            (Some("server.blocked-ip"), &Method::GET) => {
                match self.core.reload_blocked_ips().await {
                    Ok(result) => {
                        // Increment version counter
                        self.core.network.blocked_ips.increment_version();

                        JsonResponse::new(json!({
                            "data": result.config,
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (_, &Method::GET) => {
                match self.core.reload().await {
                    Ok(result) => {
                        if !UrlParams::new(req.uri().query()).has_key("dry-run") {
                            if let Some(core) = result.new_core {
                                // Update core
                                self.shared_core.store(core.into());

                                // Increment version counter
                                self.inner.increment_config_version();
                            }

                            // Reload ACME
                            if let Err(err) =
                                self.inner.housekeeper_tx.send(Event::AcmeReload).await
                            {
                                tracing::warn!(
                                    "Failed to send ACME reload event to housekeeper: {}",
                                    err
                                );
                            }
                        }

                        JsonResponse::new(json!({
                            "data": result.config,
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }

    pub async fn handle_manage_update(&self, req: &HttpRequest, path: Vec<&str>) -> HttpResponse {
        match (path.get(1).copied(), req.method()) {
            (Some("spam-filter"), &Method::GET) => {
                match self
                    .core
                    .storage
                    .config
                    .update_config_resource("spam-filter")
                    .await
                {
                    Ok(result) => JsonResponse::new(json!({
                        "data": result,
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (Some("webadmin"), &Method::GET) => {
                match self.inner.webadmin.update_and_unpack(&self.core).await {
                    Ok(_) => JsonResponse::new(json!({
                        "data": (),
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}
