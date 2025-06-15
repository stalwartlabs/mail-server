/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{KV_BAYES_MODEL_USER, Server, auth::AccessToken};
use directory::{
    DirectoryInner, Permission, QueryBy, Type,
    backend::internal::{
        PrincipalAction, PrincipalField, PrincipalSet, PrincipalUpdate, PrincipalValue,
        SpecialSecrets,
        lookup::DirectoryStore,
        manage::{
            self, ChangedPrincipals, ManageDirectory, PrincipalList, UpdatePrincipal, not_found,
        },
    },
};
use http_proto::{request::decode_path_element, *};
use hyper::{Method, header};
use serde_json::json;
use std::future::Future;
use std::sync::Arc;
use trc::AddContext;
use utils::url_params::UrlParams;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum AccountAuthRequest {
    SetPassword { password: String },
    EnableOtpAuth { url: String },
    DisableOtpAuth { url: Option<String> },
    AddAppPassword { name: String, password: String },
    RemoveAppPassword { name: Option<String> },
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
                    serde_json::from_slice::<PrincipalSet>(body.as_deref().unwrap_or_default())
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
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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

                // Validate roles
                let tenant_id = access_token.tenant.map(|t| t.id);
                for name in principal
                    .get_str_array(PrincipalField::Roles)
                    .unwrap_or_default()
                {
                    if let Some(pinfo) = self
                        .store()
                        .get_principal_info(name)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|v| v.typ == Type::Role && v.has_tenant_access(tenant_id))
                        .or_else(|| PrincipalField::Roles.map_internal_roles(name))
                    {
                        let role_permissions =
                            self.get_role_permissions(pinfo.id).await?.finalize_as_ref();
                        let mut allowed_permissions = role_permissions.clone();
                        allowed_permissions.intersection(&access_token.permissions);
                        if allowed_permissions != role_permissions {
                            return Err(manage::error(
                                "Invalid role",
                                format!("Your account cannot grant the {name:?} role").into(),
                            ));
                        }
                    }
                }

                // Set default report domain if missing
                let report_domain = if principal.typ() == Type::Domain
                    && self
                        .core
                        .storage
                        .config
                        .get("report.domain")
                        .await
                        .is_ok_and(|v| v.is_none())
                {
                    principal.name().to_lowercase().into()
                } else {
                    None
                };

                // Create principal
                let result = self
                    .core
                    .storage
                    .data
                    .create_principal(principal, tenant_id, Some(&access_token.permissions))
                    .await?;

                // Set report domain
                if let Some(report_domain) = report_domain {
                    if let Err(err) = self
                        .core
                        .storage
                        .config
                        .set([("report.domain", report_domain)], true)
                        .await
                    {
                        trc::error!(err.details("Failed to set report domain"));
                    }
                }

                // Increment revision
                self.increment_token_revision(result.changed_principals)
                    .await;

                Ok(JsonResponse::new(json!({
                    "data": result.id,
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
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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

                let principals = self
                    .store()
                    .list_principals(
                        filter,
                        tenant,
                        &types,
                        fields.len() != 1
                            || fields.first().is_none_or(|v| v != &PrincipalField::Name),
                        page,
                        limit,
                    )
                    .await?;

                let principals: PrincipalList<PrincipalSet> = if !count {
                    let mut expanded = PrincipalList {
                        items: Vec::with_capacity(principals.items.len()),
                        total: principals.total,
                    };

                    for principal in principals.items {
                        expanded
                            .items
                            .push(self.store().map_principal(principal, &fields).await?);
                    }

                    expanded
                } else {
                    PrincipalList {
                        items: vec![],
                        total: principals.total,
                    }
                };

                Ok(JsonResponse::new(json!({
                        "data": principals,
                }))
                .into_http_response())
            }
            (None, &Method::DELETE) => {
                // List principal ids
                let params = UrlParams::new(req.uri().query());
                let filter = params.get("filter");
                let typ = params.parse::<Type>("type").ok_or_else(|| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                        .into_err()
                        .details("Invalid type")
                })?;
                if params.get("confirm") != Some("true") {
                    return Err(trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                        .into_err()
                        .details("Missing confirmation parameter"));
                }

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
                    Type::Resource | Type::Location | Type::Other => Permission::PrincipalDelete,
                })?;

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
                } else if typ == Type::Tenant {
                    return Err(manage::enterprise());
                }

                let principals = self
                    .store()
                    .list_principals(filter, tenant, &[typ], false, 0, 0)
                    .await?;

                let found = !principals.items.is_empty();
                if found {
                    let server = self.clone();
                    tokio::spawn(async move {
                        let has_bayes = server
                            .core
                            .spam
                            .bayes
                            .as_ref()
                            .is_some_and(|c| c.account_classify);
                        for principal in principals.items {
                            // Delete account
                            match server
                                .store()
                                .delete_principal(QueryBy::Id(principal.id()))
                                .await
                            {
                                Ok(changed_principals) => {
                                    // Increment revision
                                    server.increment_token_revision(changed_principals).await;
                                }
                                Err(err) => {
                                    trc::error!(err.details("Failed to delete principal"));
                                    continue;
                                }
                            }

                            if matches!(typ, Type::Individual | Type::Group) {
                                // Remove FTS index
                                if let Err(err) =
                                    server.core.storage.fts.remove_all(principal.id()).await
                                {
                                    trc::error!(err.details("Failed to delete FTS index"));
                                }

                                // Delete bayes model
                                if has_bayes {
                                    let mut key =
                                        Vec::with_capacity(std::mem::size_of::<u32>() + 1);
                                    key.push(KV_BAYES_MODEL_USER);
                                    key.extend_from_slice(&principal.id().to_be_bytes());

                                    if let Err(err) =
                                        server.in_memory_store().key_delete_prefix(&key).await
                                    {
                                        trc::error!(
                                            err.details("Failed to delete user bayes model")
                                        );
                                    }
                                }
                            }
                        }
                    });
                }

                Ok(JsonResponse::new(json!({
                    "data": found,
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
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
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

                        let principal = self
                            .store()
                            .query(QueryBy::Id(account_id), true)
                            .await?
                            .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                        // Map fields
                        let principal = self
                            .core
                            .storage
                            .data
                            .map_principal(principal, &[])
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
                        let changed_principals = self
                            .store()
                            .delete_principal(QueryBy::Id(account_id))
                            .await?;

                        if matches!(typ, Type::Individual | Type::Group) {
                            // Remove FTS index
                            self.core.storage.fts.remove_all(account_id).await?;

                            // Delete bayes model
                            if self
                                .core
                                .spam
                                .bayes
                                .as_ref()
                                .is_some_and(|c| c.account_classify)
                            {
                                let mut key = Vec::with_capacity(std::mem::size_of::<u32>() + 1);
                                key.push(KV_BAYES_MODEL_USER);
                                key.extend_from_slice(&account_id.to_be_bytes());

                                if let Err(err) =
                                    self.in_memory_store().key_delete_prefix(&key).await
                                {
                                    trc::error!(err.details("Failed to delete user bayes model"));
                                }
                            }
                        }

                        // Increment revision
                        self.increment_token_revision(changed_principals).await;

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
                        for change in &changes {
                            match change.field {
                                PrincipalField::Secrets => {
                                    self.assert_supported_directory()?;
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
                                | PrincipalField::Urls
                                | PrincipalField::ExternalMembers => (),
                                PrincipalField::Tenant => {
                                    // Tenants are not allowed to change their tenantId
                                    if access_token.tenant.is_some() {
                                        trc::bail!(
                                            trc::SecurityEvent::Unauthorized
                                                .into_err()
                                                .details(permission_needed.name())
                                                .ctx(
                                                    trc::Key::Reason,
                                                    "Tenants cannot change their tenantId"
                                                )
                                        );
                                    }
                                }
                                PrincipalField::Roles
                                | PrincipalField::EnabledPermissions
                                | PrincipalField::DisabledPermissions => {
                                    if change.field == PrincipalField::Roles
                                        && matches!(
                                            change.action,
                                            PrincipalAction::AddItem | PrincipalAction::Set
                                        )
                                    {
                                        let roles = match &change.value {
                                            PrincipalValue::String(v) => std::slice::from_ref(v),
                                            PrincipalValue::StringList(vec) => vec,
                                            PrincipalValue::Integer(_)
                                            | PrincipalValue::IntegerList(_) => continue,
                                        };

                                        // Validate roles
                                        let tenant_id = access_token.tenant.map(|t| t.id);
                                        for name in roles {
                                            if let Some(pinfo) = self
                                                .store()
                                                .get_principal_info(name)
                                                .await
                                                .caused_by(trc::location!())?
                                                .filter(|v| {
                                                    v.typ == Type::Role
                                                        && v.has_tenant_access(tenant_id)
                                                })
                                                .or_else(|| {
                                                    PrincipalField::Roles.map_internal_roles(name)
                                                })
                                            {
                                                let role_permissions = self
                                                    .get_role_permissions(pinfo.id)
                                                    .await?
                                                    .finalize_as_ref();
                                                let mut allowed_permissions =
                                                    role_permissions.clone();
                                                allowed_permissions
                                                    .intersection(&access_token.permissions);
                                                if allowed_permissions != role_permissions {
                                                    return Err(manage::error(
                                                        "Invalid role",
                                                        format!("Your account cannot grant the {name:?} role").into(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Update principal
                        let changed_principals = self
                            .core
                            .storage
                            .data
                            .update_principal(
                                UpdatePrincipal::by_id(account_id)
                                    .with_updates(changes)
                                    .with_tenant(access_token.tenant.map(|t| t.id))
                                    .with_allowed_permissions(&access_token.permissions),
                            )
                            .await?;

                        // Increment revision
                        self.increment_token_revision(changed_principals).await;

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
                .directory()
                .query(QueryBy::Id(access_token.primary_id()), false)
                .await?
                .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

            for secret in &principal.secrets {
                if secret.is_otp_auth() {
                    response.otp_auth = true;
                } else if let Some((app_name, _)) =
                    secret.strip_prefix("$app$").and_then(|s| s.split_once('$'))
                {
                    response.app_passwords.push(app_name.into());
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
            .is_none_or(|header| !header.to_lowercase().starts_with("basic "))
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
                        .set(
                            [("authentication.fallback-admin.secret", password.to_string())],
                            true,
                        )
                        .await?;

                    // Increment revision
                    self.increment_token_revision(ChangedPrincipals::from_change(
                        access_token.primary_id(),
                        Type::Individual,
                        PrincipalField::Secrets,
                    ))
                    .await;

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
                    url.unwrap_or_else(|| "otpauth://".into()),
                ),
                AccountAuthRequest::AddAppPassword { name, password } => {
                    (PrincipalAction::AddItem, format!("$app${name}${password}"))
                }
                AccountAuthRequest::RemoveAppPassword { name } => (
                    PrincipalAction::RemoveItem,
                    format!("$app${}", name.unwrap_or_default()),
                ),
            };

            actions.push(PrincipalUpdate {
                action,
                field: PrincipalField::Secrets,
                value: PrincipalValue::String(secret),
            });
        }

        // Update password
        let changed_principals = self
            .core
            .storage
            .data
            .update_principal(
                UpdatePrincipal::by_id(access_token.primary_id())
                    .with_updates(actions)
                    .with_tenant(access_token.tenant.map(|t| t.id)),
            )
            .await?;

        // Increment revision
        self.increment_token_revision(changed_principals).await;

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
