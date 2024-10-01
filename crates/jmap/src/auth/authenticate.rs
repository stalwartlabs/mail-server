/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{auth::AuthRequest, listener::limiter::InFlight, Server};
use hyper::header;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use utils::map::ttl_dashmap::TtlMap;

use crate::api::{http::HttpSessionData, HttpRequest};

use common::auth::AccessToken;
use std::future::Future;

use super::rate_limit::RateLimiter;

pub trait Authenticator: Sync + Send {
    fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
        allow_api_access: bool,
    ) -> impl Future<Output = trc::Result<(InFlight, Arc<AccessToken>)>> + Send;
}

impl Authenticator for Server {
    async fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
        allow_api_access: bool,
    ) -> trc::Result<(InFlight, Arc<AccessToken>)> {
        if let Some((mechanism, token)) = req.authorization() {
            let access_token =
                if let Some(account_id) = self.inner.data.http_auth_cache.get_with_ttl(token) {
                    self.get_cached_access_token(account_id).await?
                } else {
                    let credentials = if mechanism.eq_ignore_ascii_case("basic") {
                        // Throttle authentication requests
                        self.is_auth_allowed_soft(&session.remote_ip).await?;

                        // Decode the base64 encoded credentials
                        decode_plain_auth(token).ok_or_else(|| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details("Failed to decode Basic auth request.")
                                .id(token.to_string())
                                .caused_by(trc::location!())
                        })?
                    } else if mechanism.eq_ignore_ascii_case("bearer") {
                        // Enforce anonymous rate limit
                        self.is_anonymous_allowed(&session.remote_ip).await?;

                        decode_bearer_token(token, allow_api_access).ok_or_else(|| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details("Failed to decode Bearer token.")
                                .id(token.to_string())
                                .caused_by(trc::location!())
                        })?
                    } else {
                        // Enforce anonymous rate limit
                        self.is_anonymous_allowed(&session.remote_ip).await?;

                        return Err(trc::AuthEvent::Error
                            .into_err()
                            .reason("Unsupported authentication mechanism.")
                            .details(token.to_string())
                            .caused_by(trc::location!()));
                    };

                    // Authenticate
                    let access_token = match self
                        .authenticate(&AuthRequest::from_credentials(
                            credentials,
                            session.session_id,
                            session.remote_ip,
                        ))
                        .await
                    {
                        Ok(access_token) => access_token,
                        Err(err) => {
                            if err.matches(trc::EventType::Auth(trc::AuthEvent::Failed)) {
                                let _ = self.is_auth_allowed_hard(&session.remote_ip).await;
                            }
                            return Err(err);
                        }
                    };

                    // Cache session
                    self.cache_session(token.to_string(), &access_token);
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

fn decode_plain_auth(token: &str) -> Option<Credentials<String>> {
    base64_decode(token.as_bytes())
        .and_then(|token| String::from_utf8(token).ok())
        .and_then(|token| {
            token
                .split_once(':')
                .map(|(login, secret)| Credentials::Plain {
                    username: login.trim().to_lowercase(),
                    secret: secret.to_string(),
                })
        })
}

fn decode_bearer_token(token: &str, allow_api_access: bool) -> Option<Credentials<String>> {
    if allow_api_access {
        if let Some(token) = token.strip_prefix("api_") {
            return decode_plain_auth(token);
        }
    }

    Some(Credentials::OAuthBearer {
        token: token.to_string(),
    })
}
