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

use directory::{
    backend::internal::{manage::ManageDirectory, PrincipalUpdate},
    Directory, DirectoryError, ManagementError, Principal, QueryBy, Type,
};
use http_body_util::combinators::BoxBody;
use hyper::{body::Bytes, Method, StatusCode};
use jmap_proto::error::request::RequestError;
use serde_json::json;

use crate::JMAP;

use super::{http::ToHttpResponse, HttpRequest, JsonResponse};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PrincipalResponse {
    pub id: u32,
    #[serde(rename = "type")]
    pub typ: Type,
    pub quota: u32,
    #[serde(rename = "usedQuota")]
    pub used_quota: u32,
    pub name: String,
    pub emails: Vec<String>,
    #[serde(rename = "memberOf")]
    pub member_of: Vec<String>,
    pub description: Option<String>,
}

impl JMAP {
    pub async fn handle_manage_request(
        &self,
        req: &HttpRequest,
        body: Option<Vec<u8>>,
    ) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let mut path = req.uri().path().split('/');
        path.next();
        path.next();

        match (path.next().unwrap_or(""), path.next(), req.method()) {
            ("principal", None, &Method::POST) => {
                // Create principal
                if let Some(principal) =
                    body.and_then(|body| serde_json::from_slice::<Principal<String>>(&body).ok())
                {
                    match self.store.create_account(principal).await {
                        Ok(account_id) => JsonResponse::new(json!({
                            "accountId": account_id,
                            "status": "success",
                        }))
                        .into_http_response(),
                        Err(err) => map_directory_error(err),
                    }
                } else {
                    RequestError::blank(
                        StatusCode::BAD_REQUEST.as_u16(),
                        "Invalid parameters",
                        "Failed to deserialize principal object",
                    )
                    .into_http_response()
                }
            }
            ("principal", None, &Method::GET) => {
                // List principal ids
                let mut from_key = None;
                let mut limit: usize = 0;

                if let Some(query) = req.uri().query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "limit" => {
                                limit = value.parse().unwrap_or_default();
                            }
                            "from" => {
                                from_key = value.into();
                            }
                            _ => {}
                        }
                    }
                }

                match self.store.list_accounts(from_key.as_deref(), limit).await {
                    Ok(accounts) => JsonResponse::new(json!({
                            "status": "success",
                            "data": accounts,
                    }))
                    .into_http_response(),
                    Err(err) => map_directory_error(err),
                }
            }
            ("principal", Some(name), method) => {
                // Fetch, update or delete principal
                let account_id = match self.store.get_account_id(name).await {
                    Ok(Some(account_id)) => account_id,
                    Ok(None) => {
                        return RequestError::blank(
                            StatusCode::NOT_FOUND.as_u16(),
                            "Not found",
                            "Account not found.",
                        )
                        .into_http_response();
                    }
                    Err(err) => {
                        return map_directory_error(err);
                    }
                };

                match *method {
                    Method::GET => {
                        let result = match self.store.query(QueryBy::Id(account_id)).await {
                            Ok(Some(principal)) => self.store.map_group_ids(principal).await,
                            Ok(None) => {
                                return RequestError::blank(
                                    StatusCode::NOT_FOUND.as_u16(),
                                    "Not found",
                                    "Account not found.",
                                )
                                .into_http_response()
                            }
                            Err(err) => Err(err),
                        };

                        match result {
                            Ok(principal) => {
                                // Obtain quota usage
                                let mut principal = PrincipalResponse::from(principal);
                                principal.used_quota =
                                    self.get_used_quota(account_id).await.unwrap_or_default()
                                        as u32;

                                JsonResponse::new(json!({
                                        "status": "success",
                                        "data": principal,
                                }))
                                .into_http_response()
                            }
                            Err(err) => map_directory_error(err),
                        }
                    }
                    Method::DELETE => {
                        // Remove FTS index
                        if let Err(err) = self.fts_store.remove_all(account_id).await {
                            tracing::warn!(
                                context = "fts",
                                event = "error",
                                reason = ?err,
                                "Failed to remove FTS index"
                            );
                            return RequestError::blank(
                                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                "Failed to remove FTS index",
                                "Contact the administrator if this problem persists",
                            )
                            .into_http_response();
                        }

                        // Delete account
                        match self.store.delete_account(QueryBy::Id(account_id)).await {
                            Ok(_) => JsonResponse::new(json!({
                                "status": "success",
                            }))
                            .into_http_response(),
                            Err(err) => map_directory_error(err),
                        }
                    }
                    Method::PUT => {
                        if let Some(changes) = body.and_then(|body| {
                            serde_json::from_slice::<Vec<PrincipalUpdate>>(&body).ok()
                        }) {
                            match self
                                .store
                                .update_account(QueryBy::Id(account_id), changes)
                                .await
                            {
                                Ok(account_id) => JsonResponse::new(json!({
                                    "accountId": account_id,
                                    "status": "success",
                                }))
                                .into_http_response(),
                                Err(err) => map_directory_error(err),
                            }
                        } else {
                            RequestError::blank(
                                StatusCode::BAD_REQUEST.as_u16(),
                                "Invalid parameters",
                                "Failed to deserialize modify request",
                            )
                            .into_http_response()
                        }
                    }
                    _ => RequestError::not_found().into_http_response(),
                }
            }
            ("store", Some("purge"), &Method::GET) => {
                match self.store.purge_blobs(self.blob_store.clone()).await {
                    Ok(_) => match self.store.purge_bitmaps().await {
                        Ok(_) => JsonResponse::new(json!({
                            "status": "success",
                        }))
                        .into_http_response(),
                        Err(err) => RequestError::blank(
                            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                            "Purge database failed",
                            err.to_string(),
                        )
                        .into_http_response(),
                    },
                    Err(err) => RequestError::blank(
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        "Purge blob failed",
                        err.to_string(),
                    )
                    .into_http_response(),
                }
            }
            (path_1 @ ("queue" | "report"), Some(path_2), &Method::GET) => {
                self.smtp
                    .handle_manage_request(req.uri(), req.method(), path_1, path_2)
                    .await
            }
            _ => RequestError::not_found().into_http_response(),
        }
    }
}

fn map_directory_error(err: DirectoryError) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
    match err {
        DirectoryError::Management(err) => {
            let response = match err {
                ManagementError::MissingField(details) => json!({
                    "status": "missingField",
                    "details": details,
                }),
                ManagementError::NotUniqueField(details) => json!({
                    "status": "notUniqueField",
                    "details": details,
                }),
                ManagementError::NotFound(details) => json!({
                    "status": "notFound",
                    "details": details,
                }),
            };
            JsonResponse::new(response).into_http_response()
        }
        DirectoryError::Unsupported => JsonResponse::new(json!({
            "status": "unsupported",
            "details": "Requested action is unsupported",
        }))
        .into_http_response(),
        err => {
            tracing::warn!(
                context = "directory",
                event = "error",
                reason = ?err,
                "Directory error"
            );

            RequestError::blank(
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "Database error",
                "Contact the administrator if this problem persists",
            )
            .into_http_response()
        }
    }
}

impl From<Principal<String>> for PrincipalResponse {
    fn from(principal: Principal<String>) -> Self {
        PrincipalResponse {
            id: principal.id,
            typ: principal.typ,
            quota: principal.quota,
            name: principal.name,
            emails: principal.emails,
            member_of: principal.member_of,
            description: principal.description,
            used_quota: 0,
        }
    }
}
