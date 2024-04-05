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

use common::manager::SPAMFILTER_URL;
use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
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
                    Ok(result) => JsonResponse::new(json!({
                        "data": result.config,
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (_, &Method::GET) => {
                match self.core.reload().await {
                    Ok(result) => {
                        if !UrlParams::new(req.uri().query()).has_key("dry-run") {
                            // Update core
                            if let Some(core) = result.new_core {
                                self.shared_core.store(core.into());
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
                    .update_external_config(SPAMFILTER_URL)
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
                match self
                    .inner
                    .webadmin
                    .update_and_unpack(&self.core.storage.blob)
                    .await
                {
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
