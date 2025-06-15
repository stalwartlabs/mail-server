/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::auth::oauth::OAuthStatus;
use common::{
    KV_OAUTH, Server,
    auth::{
        AccessToken,
        oauth::{CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN, USER_CODE_ALPHABET, USER_CODE_LEN},
    },
};
use http_proto::*;
use serde::Deserialize;
use serde_json::json;
use std::future::Future;
use std::sync::Arc;
use store::{
    Serialize,
    dispatch::lookup::KeyValue,
    write::{Archive, Archiver},
};
use store::{
    rand::{
        Rng,
        distr::{Alphanumeric, StandardUniform},
        rng,
    },
    write::AlignedBytes,
};
use trc::AddContext;

use super::{DeviceAuthResponse, FormData, MAX_POST_LEN, OAuthCode, OAuthCodeRequest};

#[derive(Debug, serde::Serialize, Deserialize)]
pub struct OAuthMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub authorization_endpoint: String,
    pub device_authorization_endpoint: String,
    pub registration_endpoint: String,
    pub introspection_endpoint: String,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

pub trait OAuthApiHandler: Sync + Send {
    fn handle_oauth_api_request(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_oauth_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl OAuthApiHandler for Server {
    async fn handle_oauth_api_request(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        let request =
            serde_json::from_slice::<OAuthCodeRequest>(body.as_deref().unwrap_or_default())
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;

        let response = match request {
            OAuthCodeRequest::Code {
                client_id,
                redirect_uri,
                nonce,
            } => {
                // Validate clientId
                if client_id.len() > CLIENT_ID_MAX_LEN {
                    return Err(trc::ManageEvent::Error
                        .into_err()
                        .details("Client ID is invalid."));
                } else if redirect_uri
                    .as_ref()
                    .is_some_and(|uri| uri.starts_with("http://"))
                {
                    return Err(trc::ManageEvent::Error
                        .into_err()
                        .details("Redirect URI must be HTTPS."));
                }

                // Generate client code
                let client_code = rng()
                    .sample_iter(Alphanumeric)
                    .take(DEVICE_CODE_LEN)
                    .map(char::from)
                    .collect::<String>();

                // Serialize OAuth code
                let value = Archiver::new(OAuthCode {
                    status: OAuthStatus::Authorized,
                    account_id: access_token.primary_id(),
                    client_id,
                    nonce,
                    params: redirect_uri.unwrap_or_default(),
                })
                .untrusted()
                .serialize()
                .caused_by(trc::location!())?;

                // Insert client code
                self.core
                    .storage
                    .lookup
                    .key_set(
                        KeyValue::with_prefix(KV_OAUTH, client_code.as_bytes(), value)
                            .expires(self.core.oauth.oauth_expiry_auth_code),
                    )
                    .await?;

                #[cfg(not(feature = "enterprise"))]
                let is_enterprise = false;
                #[cfg(feature = "enterprise")]
                let is_enterprise = self.core.is_enterprise_edition();

                json!({
                    "data": {
                        "code": client_code,
                        "permissions": access_token.permissions(),
                        "version": env!("CARGO_PKG_VERSION"),
                        "isEnterprise": is_enterprise,
                    },
                })
            }
            OAuthCodeRequest::Device { code } => {
                let mut success = false;

                // Obtain code
                if let Some(auth_code_) = self
                    .core
                    .storage
                    .lookup
                    .key_get::<Archive<AlignedBytes>>(KeyValue::<()>::build_key(
                        KV_OAUTH,
                        code.as_bytes(),
                    ))
                    .await?
                {
                    let oauth = auth_code_
                        .unarchive::<OAuthCode>()
                        .caused_by(trc::location!())?;
                    if oauth.status == OAuthStatus::Pending {
                        let new_oauth_code = OAuthCode {
                            status: OAuthStatus::Authorized,
                            account_id: access_token.primary_id(),
                            client_id: oauth.client_id.to_string(),
                            nonce: oauth.nonce.as_ref().map(|s| s.to_string()),
                            params: Default::default(),
                        };
                        success = true;

                        // Delete issued user code
                        self.core
                            .storage
                            .lookup
                            .key_delete(KeyValue::<()>::build_key(KV_OAUTH, code.as_bytes()))
                            .await?;

                        // Update device code status
                        self.core
                            .storage
                            .lookup
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_OAUTH,
                                    oauth.params.as_bytes(),
                                    Archiver::new(new_oauth_code)
                                        .untrusted()
                                        .serialize()
                                        .caused_by(trc::location!())?,
                                )
                                .expires(self.core.oauth.oauth_expiry_auth_code),
                            )
                            .await?;
                    }
                }

                json!({
                    "data": success,
                })
            }
        };

        Ok(JsonResponse::new(response).no_cache().into_http_response())
    }

    async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let mut form_data = FormData::from_request(req, MAX_POST_LEN, session.session_id).await?;
        let client_id = form_data
            .remove("client_id")
            .filter(|client_id| client_id.len() <= CLIENT_ID_MAX_LEN)
            .ok_or_else(|| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Client ID is missing.")
            })?;
        let nonce = form_data.remove("nonce");

        // Generate device code
        let device_code = rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();

        // Generate user code
        let mut user_code = String::with_capacity(USER_CODE_LEN + 1);
        for (pos, ch) in rng()
            .sample_iter(StandardUniform)
            .take(USER_CODE_LEN)
            .map(|v: u64| char::from(USER_CODE_ALPHABET[v as usize % USER_CODE_ALPHABET.len()]))
            .enumerate()
        {
            if pos == USER_CODE_LEN / 2 {
                user_code.push('-');
            }
            user_code.push(ch);
        }

        // Add OAuth status
        let oauth_code = Archiver::new(OAuthCode {
            status: OAuthStatus::Pending,
            account_id: u32::MAX,
            client_id,
            nonce,
            params: device_code.clone(),
        })
        .untrusted()
        .serialize()
        .caused_by(trc::location!())?;

        // Insert device code
        self.core
            .storage
            .lookup
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, device_code.as_bytes(), oauth_code.clone())
                    .expires(self.core.oauth.oauth_expiry_user_code),
            )
            .await?;

        // Insert user code
        self.core
            .storage
            .lookup
            .key_set(
                KeyValue::with_prefix(KV_OAUTH, user_code.as_bytes(), oauth_code)
                    .expires(self.core.oauth.oauth_expiry_user_code),
            )
            .await?;

        // Build response
        let base_url = HttpContext::new(&session, req)
            .resolve_response_url(self)
            .await;
        Ok(JsonResponse::new(DeviceAuthResponse {
            verification_uri: format!("{base_url}/authorize"),
            verification_uri_complete: format!("{base_url}/authorize/?code={user_code}"),
            device_code,
            user_code,
            expires_in: self.core.oauth.oauth_expiry_user_code,
            interval: 5,
        })
        .no_cache()
        .into_http_response())
    }

    async fn handle_oauth_metadata(
        &self,
        req: HttpRequest,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let base_url = HttpContext::new(&session, &req)
            .resolve_response_url(self)
            .await
            .to_string();

        Ok(JsonResponse::new(OAuthMetadata {
            authorization_endpoint: format!("{base_url}/authorize/code",),
            token_endpoint: format!("{base_url}/auth/token"),
            device_authorization_endpoint: format!("{base_url}/auth/device"),
            introspection_endpoint: format!("{base_url}/auth/introspect"),
            registration_endpoint: format!("{base_url}/auth/register"),
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ],
            response_types_supported: vec![
                "code".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "id_token token".to_string(),
            ],
            scopes_supported: vec![
                "openid".to_string(),
                "offline_access".to_string(),
                "urn:ietf:params:jmap:core".to_string(),
                "urn:ietf:params:jmap:mail".to_string(),
                "urn:ietf:params:jmap:submission".to_string(),
                "urn:ietf:params:jmap:vacationresponse".to_string(),
            ],
            issuer: base_url,
        })
        .into_http_response())
    }
}
