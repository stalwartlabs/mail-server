/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc, time::Instant};

use common::listener::limiter::InFlight;
use directory::Permission;
use hyper::header;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use utils::map::ttl_dashmap::TtlMap;

use crate::{
    api::{http::HttpSessionData, HttpRequest},
    JMAP,
};

use common::auth::AccessToken;

impl JMAP {
    pub async fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
    ) -> trc::Result<(InFlight, Arc<AccessToken>)> {
        if let Some((mechanism, token)) = req.authorization() {
            let access_token = if let Some(account_id) = self.inner.sessions.get_with_ttl(token) {
                self.core.get_cached_access_token(account_id).await?
            } else {
                let access_token = if mechanism.eq_ignore_ascii_case("basic") {
                    // Enforce rate limit for authentication requests
                    self.is_auth_allowed_soft(&session.remote_ip).await?;

                    // Decode the base64 encoded credentials
                    if let Some((account, secret)) = base64_decode(token.as_bytes())
                        .and_then(|token| String::from_utf8(token).ok())
                        .and_then(|token| {
                            token.split_once(':').map(|(login, secret)| {
                                (login.trim().to_lowercase(), secret.to_string())
                            })
                        })
                    {
                        self.authenticate_plain(
                            &account,
                            &secret,
                            session.remote_ip,
                            session.session_id,
                        )
                        .await?
                    } else {
                        return Err(trc::AuthEvent::Error
                            .into_err()
                            .details("Failed to decode Basic auth request.")
                            .id(token.to_string())
                            .caused_by(trc::location!()));
                    }
                } else if mechanism.eq_ignore_ascii_case("bearer") {
                    // Enforce anonymous rate limit for bearer auth requests
                    self.is_anonymous_allowed(&session.remote_ip).await?;

                    let (account_id, _, _) =
                        self.validate_access_token("access_token", token).await?;

                    self.core.get_access_token(account_id).await?
                } else {
                    // Enforce anonymous rate limit
                    self.is_anonymous_allowed(&session.remote_ip).await?;
                    return Err(trc::AuthEvent::Error
                        .into_err()
                        .reason("Unsupported authentication mechanism.")
                        .details(token.to_string())
                        .caused_by(trc::location!()));
                };

                // Cache session
                let access_token = Arc::new(access_token);
                self.cache_session(token.to_string(), &access_token);
                self.core.cache_access_token(access_token.clone());
                access_token
            };

            // Enforce authenticated rate limit
            self.is_account_allowed(&access_token)
                .await
                .map(|in_flight| (in_flight, access_token))
        } else {
            // Enforce anonymous rate limit
            self.is_anonymous_allowed(&session.remote_ip).await?;

            Err(trc::AuthEvent::Failed
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

    pub async fn authenticate_plain(
        &self,
        username: &str,
        secret: &str,
        remote_ip: IpAddr,
        session_id: u64,
    ) -> trc::Result<AccessToken> {
        match self
            .core
            .authenticate(
                &self.core.storage.directory,
                session_id,
                &Credentials::Plain {
                    username: username.to_string(),
                    secret: secret.to_string(),
                },
                remote_ip,
                true,
            )
            .await
        {
            Ok(principal) => self
                .core
                .build_access_token(principal)
                .await
                .and_then(|token| {
                    token
                        .assert_has_permission(Permission::Authenticate)
                        .map(|_| token)
                }),
            Err(err) => {
                if !err.matches(trc::EventType::Auth(trc::AuthEvent::MissingTotp)) {
                    let _ = self.is_auth_allowed_hard(&remote_ip).await;
                }
                Err(err)
            }
        }
    }
}

pub trait HttpHeaders {
    fn authorization(&self) -> Option<(&str, &str)>;
    fn authorization_basic(&self) -> Option<&str>;
}

impl HttpHeaders for HttpRequest {
    fn authorization(&self) -> Option<(&str, &str)> {
        self.headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.split_once(' ').map(|(l, t)| (l, t.trim())))
    }

    fn authorization_basic(&self) -> Option<&str> {
        self.authorization().and_then(|(l, t)| {
            if l.eq_ignore_ascii_case("basic") {
                Some(t)
            } else {
                None
            }
        })
    }
}
