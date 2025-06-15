/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::{HttpAuthCache, Server, auth::AuthRequest, listener::limiter::InFlight};
use http_proto::{HttpRequest, HttpSessionData};
use hyper::header;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;

use common::auth::AccessToken;
use std::future::Future;

pub trait Authenticator: Sync + Send {
    fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
        allow_api_access: bool,
    ) -> impl Future<Output = trc::Result<(Option<InFlight>, Arc<AccessToken>)>> + Send;
}

impl Authenticator for Server {
    async fn authenticate_headers(
        &self,
        req: &HttpRequest,
        session: &HttpSessionData,
        allow_api_access: bool,
    ) -> trc::Result<(Option<InFlight>, Arc<AccessToken>)> {
        if let Some((mechanism, token)) = req.authorization() {
            // Check if the credentials are cached
            if let Some(http_cache) = self.inner.cache.http_auth.get(token) {
                let access_token = self.get_access_token(http_cache.account_id).await?;

                // Make sure the revision is still valid
                if access_token.revision == http_cache.revision {
                    // Enforce authenticated rate limit
                    return self
                        .is_http_authenticated_request_allowed(&access_token)
                        .await
                        .map(|in_flight| (in_flight, access_token));
                }
            }

            let credentials = if mechanism.eq_ignore_ascii_case("basic") {
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
                self.is_http_anonymous_request_allowed(&session.remote_ip)
                    .await?;

                decode_bearer_token(token, allow_api_access).ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Failed to decode Bearer token.")
                        .id(token.to_string())
                        .caused_by(trc::location!())
                })?
            } else {
                // Enforce anonymous rate limit
                self.is_http_anonymous_request_allowed(&session.remote_ip)
                    .await?;

                return Err(trc::AuthEvent::Error
                    .into_err()
                    .reason("Unsupported authentication mechanism.")
                    .details(token.to_string())
                    .caused_by(trc::location!()));
            };

            // Authenticate
            let access_token = self
                .authenticate(&AuthRequest::from_credentials(
                    credentials,
                    session.session_id,
                    session.remote_ip,
                ))
                .await?;

            // Cache credentials
            self.inner.cache.http_auth.insert(
                token.to_string(),
                HttpAuthCache {
                    account_id: access_token.primary_id(),
                    revision: access_token.revision,
                },
            );

            // Enforce authenticated rate limit
            self.is_http_authenticated_request_allowed(&access_token)
                .await
                .map(|in_flight| (in_flight, access_token))
        } else {
            // Enforce anonymous rate limit
            self.is_http_anonymous_request_allowed(&session.remote_ip)
                .await?;

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
