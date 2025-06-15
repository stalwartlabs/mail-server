/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::AccessToken,
    ipc::{BroadcastEvent, HousekeeperEvent},
};
use directory::Permission;
use hyper::Method;
use serde_json::json;
use std::future::Future;
use utils::url_params::UrlParams;

use http_proto::*;

pub trait ManageReload: Sync + Send {
    fn handle_manage_reload(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_manage_update(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManageReload for Server {
    async fn handle_manage_reload(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        // Validate the access token
        access_token.assert_has_permission(Permission::SettingsReload)?;

        match (path.get(1).copied(), req.method()) {
            (Some("lookup"), &Method::GET) => {
                let result = self.reload_lookups().await?;
                // Update core
                if let Some(core) = result.new_core {
                    self.inner.shared_core.store(core.into());
                }

                Ok(JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response())
            }
            (Some("certificate"), &Method::GET) => Ok(JsonResponse::new(json!({
                "data": self.reload_certificates().await?.config,
            }))
            .into_http_response()),
            (Some("server.blocked-ip"), &Method::GET) => {
                let result = self.reload_blocked_ips().await?;

                self.cluster_broadcast(BroadcastEvent::ReloadBlockedIps)
                    .await;

                Ok(JsonResponse::new(json!({
                    "data": result.config,
                }))
                .into_http_response())
            }
            (_, &Method::GET) => {
                let result = self.reload().await?;
                if !UrlParams::new(req.uri().query()).has_key("dry-run") {
                    if let Some(core) = result.new_core {
                        // Update core
                        self.inner.shared_core.store(core.into());

                        self.cluster_broadcast(BroadcastEvent::ReloadSettings).await;
                    }

                    if let Some(tracers) = result.tracers {
                        // Update tracers
                        #[cfg(feature = "enterprise")]
                        tracers.update(self.inner.shared_core.load().is_enterprise_edition());
                        #[cfg(not(feature = "enterprise"))]
                        tracers.update(false);
                    }

                    // Reload settings
                    self.inner
                        .ipc
                        .housekeeper_tx
                        .send(HousekeeperEvent::ReloadSettings)
                        .await
                        .map_err(|err| {
                            trc::EventType::Server(trc::ServerEvent::ThreadError)
                                .reason(err)
                                .details(concat!(
                                    "Failed to send settings reload ",
                                    "event to housekeeper"
                                ))
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

    async fn handle_manage_update(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1).copied(), req.method()) {
            (Some("spam-filter"), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::SpamFilterUpdate)?;
                let params = UrlParams::new(req.uri().query());

                let overwrite = params.has_key("overwrite");
                let force = params.has_key("force");

                Ok(JsonResponse::new(json!({
                    "data": self
                    .core
                    .storage
                    .config
                    .update_spam_rules(force, overwrite)
                    .await?
                    .map(|v| v.to_string()),
                }))
                .into_http_response())
            }
            (Some("webadmin"), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::WebadminUpdate)?;

                self.inner
                    .data
                    .webadmin
                    .update_and_unpack(&self.core)
                    .await?;

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
