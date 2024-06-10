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

pub mod dkim;
pub mod domain;
pub mod log;
pub mod principal;
pub mod queue;
pub mod reload;
pub mod report;
pub mod settings;
pub mod sieve;
pub mod stores;

use std::{borrow::Cow, sync::Arc};

use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde::Serialize;

use crate::{auth::AccessToken, JMAP};

use super::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse};

#[derive(Serialize)]
#[serde(tag = "error")]
pub enum ManagementApiError {
    FieldAlreadyExists {
        field: Cow<'static, str>,
        value: Cow<'static, str>,
    },
    FieldMissing {
        field: Cow<'static, str>,
    },
    NotFound {
        item: Cow<'static, str>,
    },
    Unsupported {
        details: Cow<'static, str>,
    },
    AssertFailed,
    Other {
        details: Cow<'static, str>,
    },
    UnsupportedDirectoryOperation {
        class: Cow<'static, str>,
    },
}

impl JMAP {
    pub async fn handle_api_manage_request(
        &self,
        req: &HttpRequest,
        body: Option<Vec<u8>>,
        access_token: Arc<AccessToken>,
    ) -> HttpResponse {
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();
        let is_superuser = access_token.is_super_user();

        match path.first().copied().unwrap_or_default() {
            "queue" if is_superuser => self.handle_manage_queue(req, path).await,
            "settings" if is_superuser => self.handle_manage_settings(req, path, body).await,
            "reports" if is_superuser => self.handle_manage_reports(req, path).await,
            "principal" if is_superuser => self.handle_manage_principal(req, path, body).await,
            "domain" if is_superuser => self.handle_manage_domain(req, path).await,
            "store" if is_superuser => self.handle_manage_store(req, path).await,
            "reload" if is_superuser => self.handle_manage_reload(req, path).await,
            "dkim" if is_superuser => self.handle_manage_dkim(req, path, body).await,
            "update" if is_superuser => self.handle_manage_update(req, path).await,
            "logs" if is_superuser && req.method() == Method::GET => {
                self.handle_view_logs(req).await
            }
            "sieve" if is_superuser => self.handle_run_sieve(req, path, body).await,
            "restart" if is_superuser && req.method() == Method::GET => {
                ManagementApiError::Unsupported {
                    details: "Restart is not yet supported".into(),
                }
                .into_http_response()
            }
            "oauth" => self.handle_oauth_api_request(access_token, body).await,
            "crypto" => match *req.method() {
                Method::POST => self.handle_crypto_post(access_token, body).await,
                Method::GET => self.handle_crypto_get(access_token).await,
                _ => RequestError::not_found().into_http_response(),
            },
            "password" if req.method() == Method::POST => {
                self.handle_change_password(req, access_token, body).await
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}

impl ToHttpResponse for ManagementApiError {
    fn into_http_response(self) -> super::HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl From<Cow<'static, str>> for ManagementApiError {
    fn from(details: Cow<'static, str>) -> Self {
        ManagementApiError::Other { details }
    }
}

impl From<String> for ManagementApiError {
    fn from(details: String) -> Self {
        ManagementApiError::Other {
            details: details.into(),
        }
    }
}

pub fn decode_path_element(item: &str) -> Cow<'_, str> {
    // Bit hackish but avoids an extra dependency
    form_urlencoded::parse(item.as_bytes())
        .into_iter()
        .next()
        .map(|(k, _)| k)
        .unwrap_or_else(|| item.into())
}
