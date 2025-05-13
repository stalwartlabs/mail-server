/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{
    auth::{oauth::oidc::Userinfo, AccessToken},
    Server,
};
use serde::{Deserialize, Serialize};

use crate::api::{
    http::{HttpContext, HttpSessionData, ToHttpResponse},
    HttpRequest, HttpResponse, JsonResponse,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub registration_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub claims_supported: Vec<String>,
}

pub trait OpenIdHandler: Sync + Send {
    fn handle_userinfo_request(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oidc_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl OpenIdHandler for Server {
    async fn handle_userinfo_request(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        Ok(JsonResponse::new(Userinfo {
            sub: Some(access_token.primary_id.to_string()),
            name: access_token.description.clone(),
            preferred_username: Some(access_token.name.clone()),
            email: access_token.emails.first().cloned(),
            email_verified: !access_token.emails.is_empty(),
            ..Default::default()
        })
        .no_cache()
        .into_http_response())
    }

    async fn handle_oidc_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let base_url = HttpContext::new(&session, &req)
            .resolve_response_url(self)
            .await;

        Ok(JsonResponse::new(OpenIdMetadata {
            authorization_endpoint: format!("{base_url}/authorize/code",),
            token_endpoint: format!("{base_url}/auth/token"),
            userinfo_endpoint: format!("{base_url}/auth/userinfo"),
            jwks_uri: format!("{base_url}/auth/jwks.json"),
            registration_endpoint: format!("{base_url}/auth/register"),
            response_types_supported: vec![
                "code".to_string(),
                "id_token".to_string(),
                "id_token token".to_string(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            scopes_supported: vec!["openid".to_string(), "offline_access".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![
                "RS256".to_string(),
                "RS384".to_string(),
                "RS512".to_string(),
                "ES256".to_string(),
                "ES384".to_string(),
                "PS256".to_string(),
                "PS384".to_string(),
                "PS512".to_string(),
                "HS256".to_string(),
                "HS384".to_string(),
                "HS512".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "name".to_string(),
                "preferred_username".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
            ],
            issuer: base_url,
        })
        .into_http_response())
    }
}
