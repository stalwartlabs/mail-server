/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{
    Server,
    auth::{AccessToken, oauth::oidc::Userinfo},
};
use compact_str::{CompactString, ToCompactString, format_compact};
use serde::{Deserialize, Serialize};

use http_proto::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdMetadata {
    pub issuer: CompactString,
    pub authorization_endpoint: CompactString,
    pub token_endpoint: CompactString,
    pub userinfo_endpoint: CompactString,
    pub jwks_uri: CompactString,
    pub registration_endpoint: CompactString,
    pub scopes_supported: Vec<CompactString>,
    pub response_types_supported: Vec<CompactString>,
    pub subject_types_supported: Vec<CompactString>,
    pub grant_types_supported: Vec<CompactString>,
    pub id_token_signing_alg_values_supported: Vec<CompactString>,
    pub claims_supported: Vec<CompactString>,
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
            sub: Some(access_token.primary_id.to_compact_string()),
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
            authorization_endpoint: format_compact!("{base_url}/authorize/code",),
            token_endpoint: format_compact!("{base_url}/auth/token"),
            userinfo_endpoint: format_compact!("{base_url}/auth/userinfo"),
            jwks_uri: format_compact!("{base_url}/auth/jwks.json"),
            registration_endpoint: format_compact!("{base_url}/auth/register"),
            response_types_supported: vec![
                "code".into(),
                "id_token".into(),
                "id_token token".into(),
            ],
            grant_types_supported: vec![
                "authorization_code".into(),
                "implicit".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
            ],
            scopes_supported: vec!["openid".into(), "offline_access".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec![
                "RS256".into(),
                "RS384".into(),
                "RS512".into(),
                "ES256".into(),
                "ES384".into(),
                "PS256".into(),
                "PS384".into(),
                "PS512".into(),
                "HS256".into(),
                "HS384".into(),
                "HS512".into(),
            ],
            claims_supported: vec![
                "sub".into(),
                "name".into(),
                "preferred_username".into(),
                "email".into(),
                "email_verified".into(),
            ],
            issuer: base_url,
        })
        .into_http_response())
    }
}
