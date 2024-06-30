/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use directory::{
    backend::internal::{
        lookup::DirectoryStore, manage::ManageDirectory, PrincipalAction, PrincipalField,
        PrincipalUpdate, PrincipalValue, SpecialSecrets,
    },
    DirectoryError, DirectoryInner, ManagementError, Principal, QueryBy, Type,
};

use hyper::{header, Method, StatusCode};
use jmap_proto::error::request::RequestError;
use serde_json::json;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    auth::AccessToken,
    JMAP,
};

use super::{decode_path_element, ManagementApiError};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PrincipalResponse {
    #[serde(default)]
    pub id: u32,
    #[serde(rename = "type")]
    pub typ: Type,
    #[serde(default)]
    pub quota: u64,
    #[serde(rename = "usedQuota")]
    #[serde(default)]
    pub used_quota: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(rename = "memberOf")]
    #[serde(default)]
    pub member_of: Vec<String>,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum AccountAuthRequest {
    SetPassword { password: String },
    EnableOtpAuth { url: String },
    DisableOtpAuth { url: Option<String> },
    AddAppPassword { name: String, password: String },
    RemoveAppPassword { name: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AccountAuthResponse {
    #[serde(rename = "otpEnabled")]
    pub otp_auth: bool,
    #[serde(rename = "isAdministrator")]
    pub is_admin: bool,
    #[serde(rename = "appPasswords")]
    pub app_passwords: Vec<String>,
}

impl JMAP {
    pub async fn handle_manage_principal(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match (path.get(1), req.method()) {
            (None, &Method::POST) => {
                // Make sure the current directory supports updates
                if let Some(response) = self.assert_supported_directory() {
                    return response;
                }

                // Create principal
                match serde_json::from_slice::<PrincipalResponse>(
                    body.as_deref().unwrap_or_default(),
                ) {
                    Ok(principal) => {
                        match self
                            .core
                            .storage
                            .data
                            .create_account(
                                Principal {
                                    id: principal.id,
                                    typ: principal.typ,
                                    quota: principal.quota,
                                    name: principal.name,
                                    secrets: principal.secrets,
                                    emails: principal.emails,
                                    member_of: principal.member_of,
                                    description: principal.description,
                                },
                                principal.members,
                            )
                            .await
                        {
                            Ok(account_id) => JsonResponse::new(json!({
                                "data": account_id,
                            }))
                            .into_http_response(),
                            Err(err) => err.into_http_response(),
                        }
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (None, &Method::GET) => {
                // List principal ids
                let params = UrlParams::new(req.uri().query());
                let filter = params.get("filter");
                let typ = params.parse("type");
                let page: usize = params.parse("page").unwrap_or(0);
                let limit: usize = params.parse("limit").unwrap_or(0);

                match self.core.storage.data.list_accounts(filter, typ).await {
                    Ok(accounts) => {
                        let (total, accounts) = if limit > 0 {
                            let offset = page.saturating_sub(1) * limit;
                            (
                                accounts.len(),
                                accounts.into_iter().skip(offset).take(limit).collect(),
                            )
                        } else {
                            (accounts.len(), accounts)
                        };

                        JsonResponse::new(json!({
                                "data": {
                                    "items": accounts,
                                    "total": total,
                                },
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (Some(name), method) => {
                // Fetch, update or delete principal
                let name = decode_path_element(name);
                let account_id = match self.core.storage.data.get_account_id(name.as_ref()).await {
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
                        return err.into_http_response();
                    }
                };

                match *method {
                    Method::GET => {
                        let result = match self
                            .core
                            .storage
                            .data
                            .query(QueryBy::Id(account_id), true)
                            .await
                        {
                            Ok(Some(principal)) => {
                                self.core.storage.data.map_group_ids(principal).await
                            }
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
                                        as u64;

                                // Obtain member names
                                for member_id in self
                                    .core
                                    .storage
                                    .data
                                    .get_members(account_id)
                                    .await
                                    .unwrap_or_default()
                                {
                                    if let Ok(Some(member_principal)) = self
                                        .core
                                        .storage
                                        .data
                                        .query(QueryBy::Id(member_id), false)
                                        .await
                                    {
                                        principal.members.push(member_principal.name);
                                    }
                                }

                                JsonResponse::new(json!({
                                        "data": principal,
                                }))
                                .into_http_response()
                            }
                            Err(err) => err.into_http_response(),
                        }
                    }
                    Method::DELETE => {
                        // Remove FTS index
                        if let Err(err) = self.core.storage.fts.remove_all(account_id).await {
                            return err.into_http_response();
                        }

                        // Delete account
                        match self
                            .core
                            .storage
                            .data
                            .delete_account(QueryBy::Id(account_id))
                            .await
                        {
                            Ok(_) => {
                                // Remove entries from cache
                                self.inner.sessions.retain(|_, id| id.item != account_id);

                                JsonResponse::new(json!({
                                    "data": (),
                                }))
                                .into_http_response()
                            }
                            Err(err) => err.into_http_response(),
                        }
                    }
                    Method::PATCH => {
                        match serde_json::from_slice::<Vec<PrincipalUpdate>>(
                            body.as_deref().unwrap_or_default(),
                        ) {
                            Ok(changes) => {
                                // Make sure the current directory supports updates
                                if let Some(response) = self.assert_supported_directory() {
                                    if changes.iter().any(|change| {
                                        !matches!(
                                            change.field,
                                            PrincipalField::Quota | PrincipalField::Description
                                        )
                                    }) {
                                        return response;
                                    }
                                }
                                let is_password_change = changes
                                    .iter()
                                    .any(|change| matches!(change.field, PrincipalField::Secrets));

                                match self
                                    .core
                                    .storage
                                    .data
                                    .update_account(QueryBy::Id(account_id), changes)
                                    .await
                                {
                                    Ok(_) => {
                                        if is_password_change {
                                            // Remove entries from cache
                                            self.inner
                                                .sessions
                                                .retain(|_, id| id.item != account_id);
                                        }

                                        JsonResponse::new(json!({
                                            "data": (),
                                        }))
                                        .into_http_response()
                                    }
                                    Err(err) => err.into_http_response(),
                                }
                            }
                            Err(err) => err.into_http_response(),
                        }
                    }
                    _ => RequestError::not_found().into_http_response(),
                }
            }

            _ => RequestError::not_found().into_http_response(),
        }
    }

    pub async fn handle_account_auth_get(&self, access_token: Arc<AccessToken>) -> HttpResponse {
        let mut response = AccountAuthResponse {
            otp_auth: false,
            is_admin: access_token.is_super_user(),
            app_passwords: Vec::new(),
        };

        if access_token.primary_id() != u32::MAX {
            match self
                .core
                .storage
                .directory
                .query(QueryBy::Id(access_token.primary_id()), false)
                .await
            {
                Ok(Some(principal)) => {
                    for secret in principal.secrets {
                        if secret.is_otp_auth() {
                            response.otp_auth = true;
                        } else if let Some((app_name, _)) =
                            secret.strip_prefix("$app$").and_then(|s| s.split_once('$'))
                        {
                            response.app_passwords.push(app_name.to_string());
                        }
                    }
                }
                Ok(None) => {
                    return RequestError::not_found().into_http_response();
                }
                Err(err) => return err.into_http_response(),
            }
        }

        JsonResponse::new(json!({
            "data": response,
        }))
        .into_http_response()
    }

    pub async fn handle_account_auth_post(
        &self,
        req: &HttpRequest,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        // Parse request
        let requests = match serde_json::from_slice::<Vec<AccountAuthRequest>>(
            body.as_deref().unwrap_or_default(),
        ) {
            Ok(request) => request,
            Err(err) => return err.into_http_response(),
        };
        if requests.is_empty() {
            return RequestError::invalid_parameters().into_http_response();
        }

        // Make sure the user authenticated using Basic auth
        if requests.iter().any(|r| {
            matches!(
                r,
                AccountAuthRequest::DisableOtpAuth { .. }
                    | AccountAuthRequest::EnableOtpAuth { .. }
                    | AccountAuthRequest::SetPassword { .. }
            )
        }) && req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map_or(true, |header| !header.to_lowercase().starts_with("basic "))
        {
            return ManagementApiError::Other {
                details: "Password changes only allowed using Basic auth".into(),
            }
            .into_http_response();
        }

        // Handle Fallback admin password changes
        if access_token.is_super_user() && access_token.primary_id() == u32::MAX {
            match requests.into_iter().next().unwrap() {
                AccountAuthRequest::SetPassword { password } => {
                    return match self
                        .core
                        .storage
                        .config
                        .set([("authentication.fallback-admin.secret", password)])
                        .await
                    {
                        Ok(_) => {
                            // Remove entries from cache
                            self.inner.sessions.retain(|_, id| id.item != u32::MAX);

                            JsonResponse::new(json!({
                                "data": (),
                            }))
                            .into_http_response()
                        }
                        Err(err) => err.into_http_response(),
                    };
                }
                _ => {
                    return ManagementApiError::Other {
                        details:
                            "Fallback administrator accounts do not support 2FA or AppPasswords"
                                .into(),
                    }
                    .into_http_response()
                }
            }
        }

        // Make sure the current directory supports updates
        if let Some(response) = self.assert_supported_directory() {
            return response;
        }

        // Build actions
        let mut actions = Vec::with_capacity(requests.len());
        for request in requests {
            let (action, secret) = match request {
                AccountAuthRequest::SetPassword { password } => {
                    actions.push(PrincipalUpdate {
                        action: PrincipalAction::RemoveItem,
                        field: PrincipalField::Secrets,
                        value: PrincipalValue::String(String::new()),
                    });

                    (PrincipalAction::AddItem, password)
                }
                AccountAuthRequest::EnableOtpAuth { url } => (PrincipalAction::AddItem, url),
                AccountAuthRequest::DisableOtpAuth { url } => (
                    PrincipalAction::RemoveItem,
                    url.unwrap_or_else(|| "otpauth://".to_string()),
                ),
                AccountAuthRequest::AddAppPassword { name, password } => {
                    (PrincipalAction::AddItem, format!("$app${name}${password}"))
                }
                AccountAuthRequest::RemoveAppPassword { name } => {
                    (PrincipalAction::RemoveItem, format!("$app${name}"))
                }
            };

            actions.push(PrincipalUpdate {
                action,
                field: PrincipalField::Secrets,
                value: PrincipalValue::String(secret),
            });
        }

        // Update password
        match self
            .core
            .storage
            .data
            .update_account(QueryBy::Id(access_token.primary_id()), actions)
            .await
        {
            Ok(_) => {
                // Remove entries from cache
                self.inner
                    .sessions
                    .retain(|_, id| id.item != access_token.primary_id());

                JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response()
            }
            Err(err) => err.into_http_response(),
        }
    }

    pub fn assert_supported_directory(&self) -> Option<HttpResponse> {
        ManagementApiError::UnsupportedDirectoryOperation {
            class: match &self.core.storage.directory.store {
                DirectoryInner::Internal(_) => return None,
                DirectoryInner::Ldap(_) => "LDAP",
                DirectoryInner::Sql(_) => "SQL",
                DirectoryInner::Imap(_) => "IMAP",
                DirectoryInner::Smtp(_) => "SMTP",
                DirectoryInner::Memory(_) => "In-Memory",
            }
            .into(),
        }
        .into_http_response()
        .into()
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
            secrets: principal.secrets,
            used_quota: 0,
            members: Vec::new(),
        }
    }
}

impl ToHttpResponse for DirectoryError {
    fn into_http_response(self) -> HttpResponse {
        match self {
            DirectoryError::Management(err) => {
                let response = match err {
                    ManagementError::MissingField(field) => ManagementApiError::FieldMissing {
                        field: field.to_string().into(),
                    },
                    ManagementError::AlreadyExists { field, value } => {
                        ManagementApiError::FieldAlreadyExists {
                            field: field.to_string().into(),
                            value: value.into(),
                        }
                    }
                    ManagementError::NotFound(details) => ManagementApiError::NotFound {
                        item: details.into(),
                    },
                };
                JsonResponse::new(response).into_http_response()
            }
            DirectoryError::Unsupported => JsonResponse::new(ManagementApiError::Unsupported {
                details: "Requested action is unsupported".into(),
            })
            .into_http_response(),
            err => {
                tracing::warn!(
                    context = "directory",
                    event = "error",
                    reason = ?err,
                    "Directory error"
                );

                RequestError::internal_server_error().into_http_response()
            }
        }
    }
}
