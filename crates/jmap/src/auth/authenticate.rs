/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc, time::Instant};

use common::{
    config::server::ServerProtocol, listener::limiter::InFlight, AuthFailureReason, AuthResult,
};
use directory::{Principal, QueryBy};
use hyper::header;
use jmap_proto::error::request::RequestError;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use utils::map::ttl_dashmap::TtlMap;

use crate::JMAP;

use super::AccessToken;

impl JMAP {
    pub async fn authenticate_headers(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
        remote_ip: IpAddr,
    ) -> Result<Option<(InFlight, Arc<AccessToken>)>, RequestError> {
        if let Some((mechanism, token)) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim().to_string())))
        {
            let session = if let Some(account_id) = self.inner.sessions.get_with_ttl(&token) {
                self.get_cached_access_token(account_id).await
            } else {
                if mechanism.eq_ignore_ascii_case("basic") {
                    // Enforce rate limit for authentication requests
                    self.is_auth_allowed_soft(&remote_ip).await?;

                    // Decode the base64 encoded credentials
                    if let Some((account, secret)) = base64_decode(token.as_bytes())
                        .and_then(|token| String::from_utf8(token).ok())
                        .and_then(|token| {
                            token.split_once(':').map(|(login, secret)| {
                                (login.trim().to_lowercase(), secret.to_string())
                            })
                        })
                    {
                        match self
                            .authenticate_plain(&account, &secret, remote_ip, ServerProtocol::Http)
                            .await
                        {
                            AuthResult::Success(access_token) => Some(access_token),
                            AuthResult::Failure(AuthFailureReason::MissingTotp) => {
                                return Err(RequestError::blank(
                                    403,
                                    "TOTP code required",
                                    concat!(
                                        "A TOTP code is required to authenticate this account. ",
                                        "Try authenticating again using 'secret$totp_token'."
                                    ),
                                ));
                            }
                            _ => None,
                        }
                    } else {
                        tracing::debug!(
                            context = "authenticate_headers",
                            token = token,
                            "Failed to decode Basic auth request.",
                        );
                        None
                    }
                } else if mechanism.eq_ignore_ascii_case("bearer") {
                    // Enforce anonymous rate limit for bearer auth requests
                    self.is_anonymous_allowed(&remote_ip).await?;

                    match self.validate_access_token("access_token", &token).await {
                        Ok((account_id, _, _)) => self.get_access_token(account_id).await,
                        Err(err) => {
                            tracing::debug!(
                                context = "authenticate_headers",
                                err = err,
                                "Failed to validate access token."
                            );
                            None
                        }
                    }
                } else {
                    // Enforce anonymous rate limit
                    self.is_anonymous_allowed(&remote_ip).await?;
                    None
                }
                .map(|access_token| {
                    let access_token = Arc::new(access_token);
                    self.cache_session(token, &access_token);
                    self.cache_access_token(access_token.clone());
                    access_token
                })
            };

            if let Some(session) = session {
                // Enforce authenticated rate limit
                Ok(Some((self.is_account_allowed(&session).await?, session)))
            } else {
                Ok(None)
            }
        } else {
            // Enforce anonymous rate limit
            self.is_anonymous_allowed(&remote_ip).await?;

            Ok(None)
        }
    }

    pub fn cache_session(&self, session_id: String, access_token: &AccessToken) {
        self.inner.sessions.insert_with_ttl(
            session_id,
            access_token.primary_id(),
            Instant::now() + self.core.jmap.session_cache_ttl,
        );
    }

    pub fn cache_access_token(&self, access_token: Arc<AccessToken>) {
        self.inner.access_tokens.insert_with_ttl(
            access_token.primary_id(),
            access_token,
            Instant::now() + self.core.jmap.session_cache_ttl,
        );
    }

    pub async fn get_cached_access_token(&self, primary_id: u32) -> Option<Arc<AccessToken>> {
        if let Some(access_token) = self.inner.access_tokens.get_with_ttl(&primary_id) {
            access_token.into()
        } else {
            // Refresh ACL token
            self.get_access_token(primary_id).await.map(|access_token| {
                let access_token = Arc::new(access_token);
                self.cache_access_token(access_token.clone());
                access_token
            })
        }
    }

    pub async fn authenticate_plain(
        &self,
        username: &str,
        secret: &str,
        remote_ip: IpAddr,
        protocol: ServerProtocol,
    ) -> AuthResult<AccessToken> {
        match self
            .core
            .authenticate(
                &self.core.storage.directory,
                &self.smtp.inner.ipc,
                &Credentials::Plain {
                    username: username.to_string(),
                    secret: secret.to_string(),
                },
                remote_ip,
                protocol,
                true,
            )
            .await
        {
            Ok(AuthResult::Success(principal)) => AuthResult::Success(AccessToken::new(principal)),
            Ok(AuthResult::Failure(reason)) => {
                if !matches!(reason, AuthFailureReason::MissingTotp) {
                    let _ = self.is_auth_allowed_hard(&remote_ip).await;
                }
                AuthResult::Failure(reason)
            }
            Err(err) => AuthResult::Failure(AuthFailureReason::InternalError(err)),
        }
    }

    pub async fn get_access_token(&self, account_id: u32) -> Option<AccessToken> {
        match self
            .core
            .storage
            .directory
            .query(QueryBy::Id(account_id), true)
            .await
        {
            Ok(Some(principal)) => self.update_access_token(AccessToken::new(principal)).await,
            _ => match &self.core.jmap.fallback_admin {
                Some((_, secret)) if account_id == u32::MAX => {
                    self.update_access_token(AccessToken::new(Principal::fallback_admin(secret)))
                        .await
                }
                _ => None,
            },
        }
    }
}
