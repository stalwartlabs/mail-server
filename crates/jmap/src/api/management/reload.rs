/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::Method;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    services::housekeeper::Event,
    JMAP,
};

impl JMAP {
    pub async fn handle_manage_reload(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied(), req.method()) {
            (Some("lookup"), &Method::GET) => {
                let result = self.core.reload_lookups().await?;
                // Update core
                if let Some(core) = result.new_core {
                    self.shared_core.store(core.into());
                }

                Ok(JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response())
            }
            (Some("certificate"), &Method::GET) => Ok(JsonResponse::new(json!({
                "data": self.core.reload_certificates().await?.config,
            }))
            .into_http_response()),
            (Some("server.blocked-ip"), &Method::GET) => {
                let result = self.core.reload_blocked_ips().await?;
                // Increment version counter
                self.core.network.blocked_ips.increment_version();

                Ok(JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response())
            }
            (_, &Method::GET) => {
                let result = self.core.reload().await?;
                if !UrlParams::new(req.uri().query()).has_key("dry-run") {
                    if let Some(core) = result.new_core {
                        // Update core
                        self.shared_core.store(core.into());

                        // Increment version counter
                        self.inner.increment_config_version();
                    }

                    // Reload ACME
                    self.inner
                        .housekeeper_tx
                        .send(Event::AcmeReload)
                        .await
                        .map_err(|err| {
                            trc::EventType::Server(trc::ServerEvent::ThreadError)
                                .reason(err)
                                .details("Failed to send ACME reload event to housekeeper")
                                .caused_by(trc::location!())
                        })?;
                }

                Ok(JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    pub async fn handle_manage_update(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied(), req.method()) {
            (Some("spam-filter"), &Method::GET) => Ok(JsonResponse::new(json!({
                "data":  self
                .core
                .storage
                .config
                .update_config_resource("spam-filter")
                .await?,
            }))
            .into_http_response()),
            (Some("webadmin"), &Method::GET) => {
                self.inner.webadmin.update_and_unpack(&self.core).await?;

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
