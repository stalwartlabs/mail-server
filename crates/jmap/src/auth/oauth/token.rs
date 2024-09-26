/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use hyper::StatusCode;
use std::future::Future;
use store::write::Bincode;

use crate::api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse};

use super::{
    ErrorType, FormData, OAuthCode, OAuthResponse, OAuthStatus, TokenResponse, MAX_POST_LEN,
};

pub trait TokenHandler: Sync + Send {
    fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        with_refresh_token: bool,
    ) -> impl Future<Output = Result<OAuthResponse, &'static str>> + Send;
}

impl TokenHandler for Server {
    // Token endpoint
    async fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session_id: u64,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let params = FormData::from_request(req, MAX_POST_LEN, session_id).await?;
        let grant_type = params.get("grant_type").unwrap_or_default();

        let mut response = TokenResponse::error(ErrorType::InvalidGrant);

        if grant_type.eq_ignore_ascii_case("authorization_code") {
            response = if let (Some(code), Some(client_id), Some(redirect_uri)) = (
                params.get("code"),
                params.get("client_id"),
                params.get("redirect_uri"),
            ) {
                // Obtain code
                match self
                    .core
                    .storage
                    .lookup
                    .key_get::<Bincode<OAuthCode>>(format!("oauth:{code}").into_bytes())
                    .await?
                {
                    Some(auth_code) => {
                        let oauth = auth_code.inner;
                        if client_id != oauth.client_id || redirect_uri != oauth.params {
                            TokenResponse::error(ErrorType::InvalidClient)
                        } else if oauth.status == OAuthStatus::Authorized {
                            // Mark this token as issued
                            self.core
                                .storage
                                .lookup
                                .key_delete(format!("oauth:{code}").into_bytes())
                                .await?;

                            // Issue token
                            self.issue_token(oauth.account_id, &oauth.client_id, true)
                                .await
                                .map(TokenResponse::Granted)
                                .map_err(|err| {
                                    trc::AuthEvent::Error
                                        .into_err()
                                        .details(err)
                                        .caused_by(trc::location!())
                                })?
                        } else {
                            TokenResponse::error(ErrorType::InvalidGrant)
                        }
                    }
                    None => TokenResponse::error(ErrorType::AccessDenied),
                }
            } else {
                TokenResponse::error(ErrorType::InvalidClient)
            };
        } else if grant_type.eq_ignore_ascii_case("urn:ietf:params:oauth:grant-type:device_code") {
            response = TokenResponse::error(ErrorType::ExpiredToken);

            if let (Some(device_code), Some(client_id)) =
                (params.get("device_code"), params.get("client_id"))
            {
                // Obtain code
                if let Some(auth_code) = self
                    .core
                    .storage
                    .lookup
                    .key_get::<Bincode<OAuthCode>>(format!("oauth:{device_code}").into_bytes())
                    .await?
                {
                    let oauth = auth_code.inner;
                    response = if oauth.client_id != client_id {
                        TokenResponse::error(ErrorType::InvalidClient)
                    } else {
                        match oauth.status {
                            OAuthStatus::Authorized => {
                                // Mark this token as issued
                                self.core
                                    .storage
                                    .lookup
                                    .key_delete(format!("oauth:{device_code}").into_bytes())
                                    .await?;

                                // Issue token
                                self.issue_token(oauth.account_id, &oauth.client_id, true)
                                    .await
                                    .map(TokenResponse::Granted)
                                    .map_err(|err| {
                                        trc::AuthEvent::Error
                                            .into_err()
                                            .details(err)
                                            .caused_by(trc::location!())
                                    })?
                            }
                            OAuthStatus::Pending => {
                                TokenResponse::error(ErrorType::AuthorizationPending)
                            }
                            OAuthStatus::TokenIssued => {
                                TokenResponse::error(ErrorType::ExpiredToken)
                            }
                        }
                    };
                }
            }
        } else if grant_type.eq_ignore_ascii_case("refresh_token") {
            if let Some(refresh_token) = params.get("refresh_token") {
                response = match self
                    .validate_access_token("refresh_token", refresh_token)
                    .await
                {
                    Ok((account_id, client_id, time_left)) => self
                        .issue_token(
                            account_id,
                            &client_id,
                            time_left <= self.core.jmap.oauth_expiry_refresh_token_renew,
                        )
                        .await
                        .map(TokenResponse::Granted)
                        .map_err(|err| {
                            trc::AuthEvent::Error
                                .into_err()
                                .details(err)
                                .caused_by(trc::location!())
                        })?,
                    Err(err) => {
                        trc::error!(err
                            .caused_by(trc::location!())
                            .details("Failed to validate refresh token")
                            .span_id(session_id));
                        TokenResponse::error(ErrorType::InvalidGrant)
                    }
                };
            } else {
                response = TokenResponse::error(ErrorType::InvalidRequest);
            }
        }

        Ok(JsonResponse::with_status(
            if response.is_error() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            },
            response,
        )
        .into_http_response())
    }

    async fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        with_refresh_token: bool,
    ) -> Result<OAuthResponse, &'static str> {
        let password_hash = self.password_hash(account_id).await?;

        Ok(OAuthResponse {
            access_token: self.encode_access_token(
                "access_token",
                account_id,
                &password_hash,
                client_id,
                self.core.jmap.oauth_expiry_token,
            )?,
            token_type: "bearer".to_string(),
            expires_in: self.core.jmap.oauth_expiry_token,
            refresh_token: if with_refresh_token {
                self.encode_access_token(
                    "refresh_token",
                    account_id,
                    &password_hash,
                    client_id,
                    self.core.jmap.oauth_expiry_refresh_token,
                )?
                .into()
            } else {
                None
            },
            scope: None,
        })
    }
}
