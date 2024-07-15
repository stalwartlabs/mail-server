/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc, time::Instant};

use common::{config::server::ServerProtocol, listener::limiter::InFlight};
use directory::{Principal, QueryBy};
use hyper::header;
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
    ) -> trc::Result<(InFlight, Arc<AccessToken>)> {
        if let Some((mechanism, token)) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim().to_string())))
        {
            let access_token = if let Some(account_id) = self.inner.sessions.get_with_ttl(&token) {
                self.get_cached_access_token(account_id).await?
            } else {
                let access_token = if mechanism.eq_ignore_ascii_case("basic") {
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
                        self.authenticate_plain(&account, &secret, remote_ip, ServerProtocol::Http)
                            .await?
                    } else {
                        return Err(trc::Cause::Authentication
                            .into_err()
                            .details("Failed to decode Basic auth request.")
                            .id(token)
                            .caused_by(trc::location!()));
                    }
                } else if mechanism.eq_ignore_ascii_case("bearer") {
                    // Enforce anonymous rate limit for bearer auth requests
                    self.is_anonymous_allowed(&remote_ip).await?;

                    let (account_id, _, _) =
                        self.validate_access_token("access_token", &token).await?;

                    self.get_access_token(account_id).await?
                } else {
                    // Enforce anonymous rate limit
                    self.is_anonymous_allowed(&remote_ip).await?;
                    return Err(trc::Cause::Authentication
                        .into_err()
                        .reason("Unsupported authentication mechanism.")
                        .details(token)
                        .caused_by(trc::location!()));
                };

                // Cache session
                let access_token = Arc::new(access_token);
                self.cache_session(token, &access_token);
                self.cache_access_token(access_token.clone());
                access_token
            };

            // Enforce authenticated rate limit
            self.is_account_allowed(&access_token)
                .await
                .map(|in_flight| (in_flight, access_token))
        } else {
            // Enforce anonymous rate limit
            self.is_anonymous_allowed(&remote_ip).await?;

            Err(trc::Cause::Authentication
                .into_err()
                .details("Missing Authorization header.")
                .caused_by(trc::location!()))
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

    pub async fn get_cached_access_token(&self, primary_id: u32) -> trc::Result<Arc<AccessToken>> {
        if let Some(access_token) = self.inner.access_tokens.get_with_ttl(&primary_id) {
            Ok(access_token)
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
    ) -> trc::Result<AccessToken> {
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
            Ok(principal) => Ok(AccessToken::new(principal)),
            Err(err) => {
                if !err.matches(trc::Cause::MissingTotp) {
                    let _ = self.is_auth_allowed_hard(&remote_ip).await;
                }
                Err(err)
            }
        }
    }

    pub async fn get_access_token(&self, account_id: u32) -> trc::Result<AccessToken> {
        match self
            .core
            .storage
            .directory
            .query(QueryBy::Id(account_id), true)
            .await
        {
            Ok(Some(principal)) => self.update_access_token(AccessToken::new(principal)).await,
            Ok(None) => Err(trc::Cause::Authentication
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!())),
            Err(err) => match &self.core.jmap.fallback_admin {
                Some((_, secret)) if account_id == u32::MAX => {
                    self.update_access_token(AccessToken::new(Principal::fallback_admin(secret)))
                        .await
                }
                _ => Err(err),
            },
        }
    }
}
