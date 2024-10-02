/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    auth::{oauth::GrantType, AccessToken},
    Server,
};
use hyper::StatusCode;
use std::future::Future;
use store::write::Bincode;

use crate::api::{
    http::{HttpContext, HttpSessionData, ToHttpResponse},
    HttpRequest, HttpResponse, JsonResponse,
};

use super::{
    registration::ClientRegistrationHandler, ErrorType, FormData, OAuthCode, OAuthResponse,
    OAuthStatus, TokenResponse, MAX_POST_LEN,
};

pub trait TokenHandler: Sync + Send {
    fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_token_introspect(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session_id: u64,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        issuer: String,
        with_refresh_token: bool,
    ) -> impl Future<Output = trc::Result<OAuthResponse>> + Send;
}

impl TokenHandler for Server {
    // Token endpoint
    async fn handle_token_request(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let params = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let grant_type = params.get("grant_type").unwrap_or_default();

        let mut response = TokenResponse::error(ErrorType::InvalidGrant);

        let issuer = HttpContext::new(&session, req)
            .resolve_response_url(self)
            .await;

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
                            // Validate client id
                            if let Some(error) = self
                                .validate_client_registration(
                                    client_id,
                                    redirect_uri.into(),
                                    oauth.account_id,
                                )
                                .await?
                            {
                                TokenResponse::error(error)
                            } else {
                                // Mark this token as issued
                                self.core
                                    .storage
                                    .lookup
                                    .key_delete(format!("oauth:{code}").into_bytes())
                                    .await?;

                                // Issue token
                                self.issue_token(oauth.account_id, &oauth.client_id, issuer, true)
                                    .await
                                    .map(TokenResponse::Granted)
                                    .map_err(|err| {
                                        trc::AuthEvent::Error
                                            .into_err()
                                            .details(err)
                                            .caused_by(trc::location!())
                                    })?
                            }
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
                                if let Some(error) = self
                                    .validate_client_registration(client_id, None, oauth.account_id)
                                    .await?
                                {
                                    TokenResponse::error(error)
                                } else {
                                    // Mark this token as issued
                                    self.core
                                        .storage
                                        .lookup
                                        .key_delete(format!("oauth:{device_code}").into_bytes())
                                        .await?;

                                    // Issue token
                                    self.issue_token(
                                        oauth.account_id,
                                        &oauth.client_id,
                                        issuer,
                                        true,
                                    )
                                    .await
                                    .map(TokenResponse::Granted)
                                    .map_err(|err| {
                                        trc::AuthEvent::Error
                                            .into_err()
                                            .details(err)
                                            .caused_by(trc::location!())
                                    })?
                                }
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
                    .validate_access_token(GrantType::RefreshToken.into(), refresh_token)
                    .await
                {
                    Ok(token_info) => self
                        .issue_token(
                            token_info.account_id,
                            &token_info.client_id,
                            issuer,
                            token_info.expires_in
                                <= self.core.oauth.oauth_expiry_refresh_token_renew,
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
                            .span_id(session.session_id));
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

    async fn handle_token_introspect(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session_id: u64,
    ) -> trc::Result<HttpResponse> {
        // Parse token
        let token = FormData::from_request(req, 1024, session_id)
            .await?
            .remove("token")
            .ok_or_else(|| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Client ID is missing.")
            })?;

        self.introspect_access_token(&token, access_token)
            .await
            .map(|response| JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        issuer: String,
        with_refresh_token: bool,
    ) -> trc::Result<OAuthResponse> {
        Ok(OAuthResponse {
            access_token: self
                .encode_access_token(
                    GrantType::AccessToken,
                    account_id,
                    client_id,
                    self.core.oauth.oauth_expiry_token,
                )
                .await?,
            token_type: "bearer".to_string(),
            expires_in: self.core.oauth.oauth_expiry_token,
            refresh_token: if with_refresh_token {
                self.encode_access_token(
                    GrantType::RefreshToken,
                    account_id,
                    client_id,
                    self.core.oauth.oauth_expiry_refresh_token,
                )
                .await?
                .into()
            } else {
                None
            },
            id_token: match self.issue_id_token(account_id.to_string(), issuer, client_id) {
                Ok(id_token) => Some(id_token),
                Err(err) => {
                    trc::error!(err);
                    None
                }
            },
            scope: None,
        })
    }
}
