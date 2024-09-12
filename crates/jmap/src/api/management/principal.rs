/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::auth::AccessToken;
use directory::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, ManageDirectory},
        PrincipalAction, PrincipalField, PrincipalUpdate, PrincipalValue, SpecialSecrets,
    },
    DirectoryInner, Permission, Principal, QueryBy, Type,
};

use hyper::{header, Method};
use serde_json::json;
use trc::AddContext;
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

use super::decode_path_element;

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
    #[serde(rename = "appPasswords")]
    pub app_passwords: Vec<String>,
}

impl JMAP {
    pub async fn handle_manage_principal(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1), req.method()) {
            (None, &Method::POST) => {
                let todo = "increment role list version + implement gossip";

                // Parse principal
                let principal =
                    serde_json::from_slice::<Principal>(body.as_deref().unwrap_or_default())
                        .map_err(|err| {
                            trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                                .from_json_error(err)
                        })?;

                // Validate the access token
                access_token.assert_has_permission(match principal.typ() {
                    Type::Individual => Permission::IndividualCreate,
                    Type::Group => Permission::GroupCreate,
                    Type::List => Permission::MailingListCreate,
                    Type::Domain => Permission::DomainCreate,
                    Type::Tenant => Permission::TenantCreate,
                    Type::Role => Permission::RoleCreate,
                    Type::Resource | Type::Location | Type::Other => Permission::PrincipalCreate,
                })?;

                // Make sure the current directory supports updates
                if matches!(principal.typ(), Type::Individual | Type::Group | Type::List) {
                    self.assert_supported_directory()?;
                }

                // Validate tenant limits
                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() {
                    if let Some(tenant_id) = access_token.tenant_id {
                        let tenant = self
                            .core
                            .storage
                            .data
                            .query(QueryBy::Id(tenant_id), false)
                            .await?
                            .ok_or_else(|| {
                                trc::ManageEvent::NotFound
                                    .into_err()
                                    .caused_by(trc::location!())
                            })?;

                        let todo = "check limits";
                    }
                }

                // Create principal
                let result = self
                    .core
                    .storage
                    .data
                    .create_principal(principal, access_token.tenant_id)
                    .await?;

                Ok(JsonResponse::new(json!({
                    "data": result,
                }))
                .into_http_response())
            }
            (None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PrincipalList)?;

                // List principal ids
                let params = UrlParams::new(req.uri().query());
                let filter = params.get("filter");
                let typ = params.parse("type");
                let page: usize = params.parse("page").unwrap_or(0);
                let limit: usize = params.parse("limit").unwrap_or(0);

                let mut tenant_id = access_token.tenant_id;

                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() && tenant_id.is_none() {
                    if let Some(tenant_name) = params.get("tenant") {
                        tenant_id = self
                            .core
                            .storage
                            .data
                            .get_principal_info(tenant_name)
                            .await?
                            .filter(|p| p.typ == Type::Tenant)
                            .map(|p| p.id);
                    }
                }

                let accounts = self
                    .core
                    .storage
                    .data
                    .list_principals(filter, typ, tenant_id)
                    .await?;
                let (total, accounts) = if limit > 0 {
                    let offset = page.saturating_sub(1) * limit;
                    (
                        accounts.len(),
                        accounts.into_iter().skip(offset).take(limit).collect(),
                    )
                } else {
                    (accounts.len(), accounts)
                };

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": accounts,
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            (Some(name), method) => {
                // Validate the access token
                match *method {
                    Method::GET => {
                        access_token.assert_has_permission(Permission::PrincipalGet)?;
                    }
                    Method::DELETE => {
                        access_token.assert_has_permission(Permission::PrincipalDelete)?;
                    }
                    Method::PATCH => {
                        access_token.assert_has_permission(Permission::PrincipalUpdate)?;
                    }
                    _ => {}
                }

                // Fetch, update or delete principal
                let name = decode_path_element(name);
                let account_id = self
                    .core
                    .storage
                    .data
                    .get_principal_id(name.as_ref())
                    .await?
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                match *method {
                    Method::GET => {
                        let mut principal = self
                            .core
                            .storage
                            .data
                            .query(QueryBy::Id(account_id), true)
                            .await?
                            .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                        // Map groups
                        if let Some(member_of) = principal.take_int_array(PrincipalField::MemberOf)
                        {
                            for principal_id in member_of {
                                if let Some(name) = self
                                    .core
                                    .storage
                                    .data
                                    .get_principal_name(principal_id as u32)
                                    .await
                                    .caused_by(trc::location!())?
                                {
                                    principal.append_str(PrincipalField::MemberOf, name);
                                }
                            }
                        }

                        // Obtain quota usage
                        principal.set(
                            PrincipalField::UsedQuota,
                            self.get_used_quota(account_id).await? as u64,
                        );

                        // Obtain member names
                        for member_id in self.core.storage.data.get_members(account_id).await? {
                            if let Some(mut member_principal) = self
                                .core
                                .storage
                                .data
                                .query(QueryBy::Id(member_id), false)
                                .await?
                            {
                                if let Some(name) = member_principal.take_str(PrincipalField::Name)
                                {
                                    principal.append_str(PrincipalField::Members, name);
                                }
                            }
                        }

                        Ok(JsonResponse::new(json!({
                                "data": principal,
                        }))
                        .into_http_response())
                    }
                    Method::DELETE => {
                        // Remove FTS index
                        self.core.storage.fts.remove_all(account_id).await?;

                        // Delete account
                        self.core
                            .storage
                            .data
                            .delete_principal(QueryBy::Id(account_id))
                            .await?;
                        // Remove entries from cache
                        self.inner.sessions.retain(|_, id| id.item != account_id);

                        Ok(JsonResponse::new(json!({
                            "data": (),
                        }))
                        .into_http_response())
                    }
                    Method::PATCH => {
                        let changes = serde_json::from_slice::<Vec<PrincipalUpdate>>(
                            body.as_deref().unwrap_or_default(),
                        )
                        .map_err(|err| {
                            trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                                .from_json_error(err)
                        })?;

                        // Make sure the current directory supports updates
                        if changes.iter().any(|change| {
                            !matches!(
                                change.field,
                                PrincipalField::Quota | PrincipalField::Description
                            )
                        }) {
                            self.assert_supported_directory()?;
                        }

                        let is_password_change = changes
                            .iter()
                            .any(|change| matches!(change.field, PrincipalField::Secrets));

                        self.core
                            .storage
                            .data
                            .update_principal(QueryBy::Id(account_id), changes)
                            .await?;
                        if is_password_change {
                            // Remove entries from cache
                            self.inner.sessions.retain(|_, id| id.item != account_id);
                        }

                        Ok(JsonResponse::new(json!({
                            "data": (),
                        }))
                        .into_http_response())
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }

            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    pub async fn handle_account_auth_get(
        &self,
        access_token: Arc<AccessToken>,
    ) -> trc::Result<HttpResponse> {
        let mut response = AccountAuthResponse {
            otp_auth: false,
            app_passwords: Vec::new(),
        };

        if access_token.primary_id() != u32::MAX {
            let principal = self
                .core
                .storage
                .directory
                .query(QueryBy::Id(access_token.primary_id()), false)
                .await?
                .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

            for secret in principal.iter_str(PrincipalField::Secrets) {
                if secret.is_otp_auth() {
                    response.otp_auth = true;
                } else if let Some((app_name, _)) =
                    secret.strip_prefix("$app$").and_then(|s| s.split_once('$'))
                {
                    response.app_passwords.push(app_name.to_string());
                }
            }
        }

        Ok(JsonResponse::new(json!({
            "data": response,
        }))
        .into_http_response())
    }

    pub async fn handle_account_auth_post(
        &self,
        req: &HttpRequest,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        // Parse request
        let requests =
            serde_json::from_slice::<Vec<AccountAuthRequest>>(body.as_deref().unwrap_or_default())
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

        if requests.is_empty() {
            return Err(trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                .into_err()
                .details("Empty request"));
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
            return Err(manage::error(
                "Password changes only allowed using Basic auth",
                None::<u32>,
            ));
        }

        // Handle Fallback admin password changes
        if access_token.primary_id() == u32::MAX {
            match requests.into_iter().next().unwrap() {
                AccountAuthRequest::SetPassword { password } => {
                    self.core
                        .storage
                        .config
                        .set([("authentication.fallback-admin.secret", password)])
                        .await?;

                    // Remove entries from cache
                    self.inner.sessions.retain(|_, id| id.item != u32::MAX);

                    return Ok(JsonResponse::new(json!({
                        "data": (),
                    }))
                    .into_http_response());
                }
                _ => {
                    return Err(manage::error(
                        "Fallback administrator accounts do not support 2FA or AppPasswords",
                        None::<u32>,
                    ));
                }
            }
        }

        // Make sure the current directory supports updates
        self.assert_supported_directory()?;

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
        self.core
            .storage
            .data
            .update_principal(QueryBy::Id(access_token.primary_id()), actions)
            .await?;

        // Remove entries from cache
        self.inner
            .sessions
            .retain(|_, id| id.item != access_token.primary_id());

        Ok(JsonResponse::new(json!({
            "data": (),
        }))
        .into_http_response())
    }

    pub fn assert_supported_directory(&self) -> trc::Result<()> {
        let class = match &self.core.storage.directory.store {
            DirectoryInner::Internal(_) => return Ok(()),
            DirectoryInner::Ldap(_) => "LDAP",
            DirectoryInner::Sql(_) => "SQL",
            DirectoryInner::Imap(_) => "IMAP",
            DirectoryInner::Smtp(_) => "SMTP",
            DirectoryInner::Memory(_) => "In-Memory",
        };

        Err(manage::unsupported(format!(
            concat!(
                "{} directory cannot be managed. ",
                "Only internal directories support inserts ",
                "and update operations."
            ),
            class
        )))
    }
}
