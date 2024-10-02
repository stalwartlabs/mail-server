/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc, time::Instant};

use directory::{
    core::secret::verify_secret_hash, Directory, Permission, Permissions, Principal, QueryBy,
};
use jmap_proto::types::collection::Collection;
use mail_send::Credentials;
use oauth::GrantType;
use utils::map::{bitmap::Bitmap, ttl_dashmap::TtlMap, vec_map::VecMap};

use crate::Server;

pub mod access_token;
pub mod oauth;
pub mod roles;
pub mod sasl;

#[derive(Debug, Clone, Default)]
pub struct AccessToken {
    pub primary_id: u32,
    pub member_of: Vec<u32>,
    pub access_to: VecMap<u32, Bitmap<Collection>>,
    pub name: String,
    pub description: Option<String>,
    pub emails: Vec<String>,
    pub quota: u64,
    pub permissions: Permissions,
    pub tenant: Option<TenantInfo>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantInfo {
    pub id: u32,
    pub quota: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceToken {
    pub account_id: u32,
    pub quota: u64,
    pub tenant: Option<TenantInfo>,
}

pub struct AuthRequest<'x> {
    credentials: Credentials<String>,
    session_id: u64,
    remote_ip: IpAddr,
    return_member_of: bool,
    directory: Option<&'x Directory>,
}

impl Server {
    pub async fn authenticate(&self, req: &AuthRequest<'_>) -> trc::Result<Arc<AccessToken>> {
        // Resolve directory
        let directory = req.directory.unwrap_or(&self.core.storage.directory);

        // Validate credentials
        match &req.credentials {
            Credentials::OAuthBearer { token } if !directory.has_bearer_token_support() => {
                match self
                    .validate_access_token(GrantType::AccessToken.into(), token)
                    .await
                {
                    Ok(token_into) => self.get_cached_access_token(token_into.account_id).await,
                    Err(err) => Err(err),
                }
            }
            _ => match self.authenticate_credentials(req, directory).await {
                Ok(principal) => {
                    if let Some(access_token) =
                        self.inner.data.access_tokens.get_with_ttl(&principal.id())
                    {
                        Ok(access_token)
                    } else {
                        self.build_access_token(principal)
                            .await
                            .map(|access_token| {
                                let access_token = Arc::new(access_token);
                                self.cache_access_token(access_token.clone());
                                access_token
                            })
                    }
                }
                Err(err) => Err(err),
            },
        }
        .and_then(|token| {
            token
                .assert_has_permission(Permission::Authenticate)
                .map(|_| token)
        })
    }

    async fn authenticate_credentials(
        &self,
        req: &AuthRequest<'_>,
        directory: &Directory,
    ) -> trc::Result<Principal> {
        // First try to authenticate the user against the default directory
        let result = match directory
            .query(QueryBy::Credentials(&req.credentials), req.return_member_of)
            .await
        {
            Ok(Some(principal)) => {
                trc::event!(
                    Auth(trc::AuthEvent::Success),
                    AccountName = principal.name().to_string(),
                    AccountId = principal.id(),
                    SpanId = req.session_id,
                );

                return Ok(principal);
            }
            Ok(None) => Ok(()),
            Err(err) => {
                if err.matches(trc::EventType::Auth(trc::AuthEvent::MissingTotp)) {
                    return Err(err);
                } else {
                    Err(err)
                }
            }
        };

        // Then check if the credentials match the fallback admin or master user
        match (
            &self.core.jmap.fallback_admin,
            &self.core.jmap.master_user,
            &req.credentials,
        ) {
            (Some((fallback_admin, fallback_pass)), _, Credentials::Plain { username, secret })
                if username == fallback_admin =>
            {
                if verify_secret_hash(fallback_pass, secret).await? {
                    trc::event!(
                        Auth(trc::AuthEvent::Success),
                        AccountName = username.clone(),
                        SpanId = req.session_id,
                    );

                    return Ok(Principal::fallback_admin(fallback_pass));
                }
            }
            (_, Some((master_user, master_pass)), Credentials::Plain { username, secret })
                if username.ends_with(master_user) =>
            {
                if verify_secret_hash(master_pass, secret).await? {
                    let username = username.strip_suffix(master_user).unwrap();
                    let username = username.strip_suffix('%').unwrap_or(username);

                    if let Some(principal) = directory
                        .query(QueryBy::Name(username), req.return_member_of)
                        .await?
                    {
                        trc::event!(
                            Auth(trc::AuthEvent::Success),
                            AccountName = username.to_string(),
                            SpanId = req.session_id,
                            AccountId = principal.id(),
                            Type = principal.typ().as_str(),
                        );

                        return Ok(principal);
                    }
                }
            }
            _ => {}
        }

        if let Err(err) = result {
            Err(err)
        } else if self.has_auth_fail2ban() {
            let login = req.credentials.login();
            if self.is_auth_fail2banned(req.remote_ip, login).await? {
                Err(trc::SecurityEvent::AuthenticationBan
                    .into_err()
                    .ctx(trc::Key::RemoteIp, req.remote_ip)
                    .ctx_opt(trc::Key::AccountName, login.map(|s| s.to_string())))
            } else {
                Err(trc::AuthEvent::Failed
                    .ctx(trc::Key::RemoteIp, req.remote_ip)
                    .ctx_opt(trc::Key::AccountName, login.map(|s| s.to_string())))
            }
        } else {
            Err(trc::AuthEvent::Failed
                .ctx(trc::Key::RemoteIp, req.remote_ip)
                .ctx_opt(
                    trc::Key::AccountName,
                    req.credentials.login().map(|s| s.to_string()),
                ))
        }
    }

    pub fn cache_session(&self, session_id: String, access_token: &AccessToken) {
        self.inner.data.http_auth_cache.insert_with_ttl(
            session_id,
            access_token.primary_id(),
            Instant::now() + self.core.jmap.session_cache_ttl,
        );
    }
}

impl<'x> AuthRequest<'x> {
    pub fn from_credentials(
        credentials: Credentials<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self {
            credentials,
            session_id,
            remote_ip,
            return_member_of: true,
            directory: None,
        }
    }

    pub fn from_plain(
        user: impl Into<String>,
        pass: impl Into<String>,
        session_id: u64,
        remote_ip: IpAddr,
    ) -> Self {
        Self::from_credentials(
            Credentials::Plain {
                username: user.into(),
                secret: pass.into(),
            },
            session_id,
            remote_ip,
        )
    }

    pub fn without_members(mut self) -> Self {
        self.return_member_of = false;
        self
    }

    pub fn with_directory(mut self, directory: &'x Directory) -> Self {
        self.directory = Some(directory);
        self
    }
}

pub(crate) trait CredentialsUsername {
    fn login(&self) -> Option<&str>;
}

impl CredentialsUsername for Credentials<String> {
    fn login(&self) -> Option<&str> {
        match self {
            Credentials::Plain { username, .. } | Credentials::XOauth2 { username, .. } => {
                username.as_str().into()
            }
            Credentials::OAuthBearer { .. } => None,
        }
    }
}
