/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::{atomic::Ordering, Arc};

use common::{auth::AccessToken, Server};
use directory::{
    backend::internal::{
        lookup::DirectoryStore,
        manage::{self, not_found, ManageDirectory, UpdatePrincipal},
        PrincipalAction, PrincipalField, PrincipalUpdate, PrincipalValue, SpecialSecrets,
    },
    DirectoryInner, Permission, Principal, QueryBy, Type,
};

use hyper::{header, Method};
use serde_json::json;
use trc::AddContext;
use utils::url_params::UrlParams;

use crate::api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse};

use super::decode_path_element;
use std::future::Future;

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

pub trait PrincipalManager: Sync + Send {
    fn handle_manage_principal(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_account_auth_get(
        &self,
        access_token: Arc<AccessToken>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_account_auth_post(
        &self,
        req: &HttpRequest,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn assert_supported_directory(&self) -> trc::Result<()>;
}

impl PrincipalManager for Server {
    async fn handle_manage_principal(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (path.get(1), req.method()) {
            (None, &Method::POST) => {
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
                    Type::ApiKey => Permission::ApiKeyCreate,
                    Type::OauthClient => Permission::OauthClientCreate,
                    Type::Resource | Type::Location | Type::Other => Permission::PrincipalCreate,
                })?;

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                if (matches!(principal.typ(), Type::Tenant)
                    || principal.has_field(PrincipalField::Tenant))
                    && !self.core.is_enterprise_edition()
                {
                    return Err(manage::enterprise());
                }

                // SPDX-SnippetEnd

                // Make sure the current directory supports updates
                if matches!(principal.typ(), Type::Individual) {
                    self.assert_supported_directory()?;
                }

                // Create principal
                let result = self
                    .core
                    .storage
                    .data
                    .create_principal(principal, access_token.tenant.map(|t| t.id))
                    .await?;

                Ok(JsonResponse::new(json!({
                    "data": result,
                }))
                .into_http_response())
            }
            (None, &Method::GET) => {
                // List principal ids
                let params = UrlParams::new(req.uri().query());
                let filter = params.get("filter");
                let page: usize = params.parse("page").unwrap_or(0);
                let limit: usize = params.parse("limit").unwrap_or(0);
                let count = params.get("count").is_some();

                // Parse types
                let mut types = Vec::new();
                for typ in params
                    .get("types")
                    .or_else(|| params.get("type"))
                    .unwrap_or_default()
                    .split(',')
                {
                    if let Some(typ) = Type::parse(typ) {
                        if !types.contains(&typ) {
                            types.push(typ);
                        }
                    }
                }

                // Parse fields
                let mut fields = Vec::new();
                for field in params.get("fields").unwrap_or_default().split(',') {
                    if let Some(field) = PrincipalField::try_parse(field) {
                        if !fields.contains(&field) {
                            fields.push(field);
                        }
                    }
                }

                // Validate the access token
                let validate_types = if !types.is_empty() {
                    types.as_slice()
                } else {
                    &[
                        Type::Individual,
                        Type::Group,
                        Type::List,
                        Type::Domain,
                        Type::Tenant,
                        Type::Role,
                        Type::Other,
                        Type::ApiKey,
                        Type::OauthClient,
                    ]
                };
                for typ in validate_types {
                    access_token.assert_has_permission(match typ {
                        Type::Individual => Permission::IndividualList,
                        Type::Group => Permission::GroupList,
                        Type::List => Permission::MailingListList,
                        Type::Domain => Permission::DomainList,
                        Type::Tenant => Permission::TenantList,
                        Type::Role => Permission::RoleList,
                        Type::ApiKey => Permission::ApiKeyList,
                        Type::OauthClient => Permission::OauthClientList,
                        Type::Resource | Type::Location | Type::Other => Permission::PrincipalList,
                    })?;
                }

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                let mut tenant = access_token.tenant.map(|t| t.id);

                #[cfg(feature = "enterprise")]
                if self.core.is_enterprise_edition() {
                    if tenant.is_none() {
                        // Limit search to current tenant
                        if let Some(tenant_name) = params.get("tenant") {
                            tenant = self
                                .core
                                .storage
                                .data
                                .get_principal_info(tenant_name)
                                .await?
                                .filter(|p| p.typ == Type::Tenant)
                                .map(|p| p.id);
                        }
                    }
                } else if types.contains(&Type::Tenant) {
                    return Err(manage::enterprise());
                }

                // SPDX-SnippetEnd

                let mut principals = self
                    .core
                    .storage
                    .data
                    .list_principals(filter, tenant, &types, &fields, page, limit)
                    .await?;

                if count {
                    principals.items.clear();
                }

                Ok(JsonResponse::new(json!({
                        "data": principals,
                }))
                .into_http_response())
            }
            (Some(name), method) => {
                // Fetch, update or delete principal
                let name = decode_path_element(name);
                let (account_id, typ) = self
                    .core
                    .storage
                    .data
                    .get_principal_info(name.as_ref())
                    .await?
                    .filter(|p| p.has_tenant_access(access_token.tenant.map(|t| t.id)))
                    .map(|p| (p.id, p.typ))
                    .ok_or_else(|| not_found(name.to_string()))?;

                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                #[cfg(feature = "enterprise")]
                if matches!(typ, Type::Tenant) && !self.core.is_enterprise_edition() {
                    return Err(manage::enterprise());
                }

                // SPDX-SnippetEnd

                match *method {
                    Method::GET => {
                        // Validate the access token
                        access_token.assert_has_permission(match typ {
                            Type::Individual => Permission::IndividualGet,
                            Type::Group => Permission::GroupGet,
                            Type::List => Permission::MailingListGet,
                            Type::Domain => Permission::DomainGet,
                            Type::Tenant => Permission::TenantGet,
                            Type::Role => Permission::RoleGet,
                            Type::ApiKey => Permission::ApiKeyGet,
                            Type::OauthClient => Permission::OauthClientGet,
                            Type::Resource | Type::Location | Type::Other => {
                                Permission::PrincipalGet
                            }
                        })?;

                        let mut principal = self
                            .core
                            .storage
                            .data
                            .query(QueryBy::Id(account_id), true)
                            .await?
                            .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                        // Map fields
                        self.core
                            .storage
                            .data
                            .map_field_ids(&mut principal, &[])
                            .await
                            .caused_by(trc::location!())?;

                        Ok(JsonResponse::new(json!({
                                "data": principal,
                        }))
                        .into_http_response())
                    }
                    Method::DELETE => {
                        // Validate the access token
                        access_token.assert_has_permission(match typ {
                            Type::Individual => Permission::IndividualDelete,
                            Type::Group => Permission::GroupDelete,
                            Type::List => Permission::MailingListDelete,
                            Type::Domain => Permission::DomainDelete,
                            Type::Tenant => Permission::TenantDelete,
                            Type::Role => Permission::RoleDelete,
                            Type::ApiKey => Permission::ApiKeyDelete,
                            Type::OauthClient => Permission::OauthClientDelete,
                            Type::Resource | Type::Location | Type::Other => {
                                Permission::PrincipalDelete
                            }
                        })?;

                        // Delete account
                        self.core
                            .storage
                            .data
                            .delete_principal(QueryBy::Id(account_id))
                            .await?;

                        // Remove FTS index
                        if matches!(typ, Type::Individual | Type::Group) {
                            self.core.storage.fts.remove_all(account_id).await?;
                        }

                        // Remove entries from cache
                        self.inner
                            .data
                            .http_auth_cache
                            .retain(|_, id| id.item != account_id);

                        if matches!(typ, Type::Role | Type::Tenant) {
                            // Update permissions cache
                            self.inner.data.permissions.clear();
                            self.inner
                                .data
                                .permissions_version
                                .fetch_add(1, Ordering::Relaxed);
                        }

                        Ok(JsonResponse::new(json!({
                            "data": (),
                        }))
                        .into_http_response())
                    }
                    Method::PATCH => {
                        // Validate the access token
                        let permission_needed = match typ {
                            Type::Individual => Permission::IndividualUpdate,
                            Type::Group => Permission::GroupUpdate,
                            Type::List => Permission::MailingListUpdate,
                            Type::Domain => Permission::DomainUpdate,
                            Type::Tenant => Permission::TenantUpdate,
                            Type::Role => Permission::RoleUpdate,
                            Type::ApiKey => Permission::ApiKeyUpdate,
                            Type::OauthClient => Permission::OauthClientUpdate,
                            Type::Resource | Type::Location | Type::Other => {
                                Permission::PrincipalUpdate
                            }
                        };
                        access_token.assert_has_permission(permission_needed)?;

                        let changes = serde_json::from_slice::<Vec<PrincipalUpdate>>(
                            body.as_deref().unwrap_or_default(),
                        )
                        .map_err(|err| {
                            trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                                .from_json_error(err)
                        })?;

                        // Validate changes
                        let mut needs_assert = false;
                        let mut expire_session = false;
                        let mut expire_token = false;
                        let mut is_role_change = false;

                        for change in &changes {
                            match change.field {
                                PrincipalField::Secrets => {
                                    expire_session = true;
                                    needs_assert = true;
                                }
                                PrincipalField::Name
                                | PrincipalField::Emails
                                | PrincipalField::Quota
                                | PrincipalField::UsedQuota
                                | PrincipalField::Description
                                | PrincipalField::Type
                                | PrincipalField::Picture
                                | PrincipalField::MemberOf
                                | PrincipalField::Members
                                | PrincipalField::Lists
                                | PrincipalField::Urls => (),
                                PrincipalField::Tenant => {
                                    // Tenants are not allowed to change their tenantId
                                    if access_token.tenant.is_some() {
                                        trc::bail!(trc::SecurityEvent::Unauthorized
                                            .into_err()
                                            .details(permission_needed.name())
                                            .ctx(
                                                trc::Key::Reason,
                                                "Tenants cannot change their tenantId"
                                            ));
                                    }
                                }
                                PrincipalField::Roles
                                | PrincipalField::EnabledPermissions
                                | PrincipalField::DisabledPermissions => {
                                    if matches!(typ, Type::Role | Type::Tenant) {
                                        is_role_change = true;
                                    } else {
                                        expire_token = true;
                                    }
                                }
                            }
                        }

                        if needs_assert {
                            self.assert_supported_directory()?;
                        }

                        // Update principal
                        self.core
                            .storage
                            .data
                            .update_principal(
                                UpdatePrincipal::by_id(account_id)
                                    .with_updates(changes)
                                    .with_tenant(access_token.tenant.map(|t| t.id)),
                            )
                            .await?;

                        if expire_session {
                            // Remove entries from cache
                            self.inner
                                .data
                                .http_auth_cache
                                .retain(|_, id| id.item != account_id);
                        }

                        if is_role_change {
                            // Update permissions cache
                            self.inner.data.permissions.clear();
                            self.inner
                                .data
                                .permissions_version
                                .fetch_add(1, Ordering::Relaxed);
                        }

                        if expire_token {
                            self.inner.data.access_tokens.remove(&account_id);
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

    async fn handle_account_auth_get(
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

    async fn handle_account_auth_post(
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
                    self.inner
                        .data
                        .http_auth_cache
                        .retain(|_, id| id.item != u32::MAX);

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
            .update_principal(
                UpdatePrincipal::by_id(access_token.primary_id())
                    .with_updates(actions)
                    .with_tenant(access_token.tenant.map(|t| t.id)),
            )
            .await?;

        // Remove entries from cache
        self.inner
            .data
            .http_auth_cache
            .retain(|_, id| id.item != access_token.primary_id());

        Ok(JsonResponse::new(json!({
            "data": (),
        }))
        .into_http_response())
    }

    fn assert_supported_directory(&self) -> trc::Result<()> {
        let class = match &self.core.storage.directory.store {
            DirectoryInner::Internal(_) => return Ok(()),
            DirectoryInner::Ldap(_) => "LDAP",
            DirectoryInner::Sql(_) => "SQL",
            DirectoryInner::Imap(_) => "IMAP",
            DirectoryInner::Smtp(_) => "SMTP",
            DirectoryInner::Memory(_) => "In-Memory",
            #[cfg(feature = "enterprise")]
            DirectoryInner::OpenId(_) => "OpenID",
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
