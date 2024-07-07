/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use hyper::StatusCode;
use rand::distributions::Standard;
use serde_json::json;
use store::{
    rand::{distributions::Alphanumeric, thread_rng, Rng},
    write::Bincode,
    Serialize,
};

use crate::{
    api::{
        http::ToHttpResponse, management::ManagementApiError, HtmlResponse, HttpRequest,
        HttpResponse, JsonResponse,
    },
    auth::{oauth::OAuthStatus, AccessToken},
    JMAP,
};
use se_common::EnterpriseCore;

use super::{
    DeviceAuthResponse, FormData, OAuthCode, OAuthCodeRequest, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN,
    MAX_POST_LEN, USER_CODE_ALPHABET, USER_CODE_LEN,
};

impl JMAP {
    pub async fn handle_oauth_api_request(
        &self,
        access_token: Arc<AccessToken>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match serde_json::from_slice::<OAuthCodeRequest>(body.as_deref().unwrap_or_default()) {
            Ok(request) => {
                let response = match request {
                    OAuthCodeRequest::Code {
                        client_id,
                        redirect_uri,
                    } => {
                        // Validate clientId
                        if client_id.len() > CLIENT_ID_MAX_LEN {
                            return ManagementApiError::Other {
                                details: "Client ID is invalid.".into(),
                            }
                            .into_http_response();
                        } else if redirect_uri
                            .as_ref()
                            .map_or(false, |uri| !uri.starts_with("https://"))
                        {
                            return ManagementApiError::Other {
                                details: "Redirect URI must be HTTPS.".into(),
                            }
                            .into_http_response();
                        }

                        // Generate client code
                        let client_code = thread_rng()
                            .sample_iter(Alphanumeric)
                            .take(DEVICE_CODE_LEN)
                            .map(char::from)
                            .collect::<String>();

                        // Serialize OAuth code
                        let value = Bincode::new(OAuthCode {
                            status: OAuthStatus::Authorized,
                            account_id: access_token.primary_id(),
                            client_id,
                            params: redirect_uri.unwrap_or_default(),
                        })
                        .serialize();

                        // Insert client code
                        if let Err(err) = self
                            .core
                            .storage
                            .lookup
                            .key_set(
                                format!("oauth:{client_code}").into_bytes(),
                                value,
                                self.core.jmap.oauth_expiry_auth_code.into(),
                            )
                            .await
                        {
                            return err.into_http_response();
                        }

                        json!({
                            "data": {
                                "code": client_code,
                                "is_admin": access_token.is_super_user(),
                                "is_enterprise": self.core.is_enterprise_edition(),
                            },
                        })
                    }
                    OAuthCodeRequest::Device { code } => {
                        let mut success = false;

                        // Obtain code
                        match self
                            .core
                            .storage
                            .lookup
                            .key_get::<Bincode<OAuthCode>>(format!("oauth:{code}").into_bytes())
                            .await
                        {
                            Ok(Some(mut auth_code))
                                if auth_code.inner.status == OAuthStatus::Pending =>
                            {
                                auth_code.inner.status = OAuthStatus::Authorized;
                                auth_code.inner.account_id = access_token.primary_id();
                                let device_code = std::mem::take(&mut auth_code.inner.params);
                                success = true;

                                // Delete issued user code
                                if let Err(err) = self
                                    .core
                                    .storage
                                    .lookup
                                    .key_delete(format!("oauth:{code}").into_bytes())
                                    .await
                                {
                                    return err.into_http_response();
                                }

                                // Update device code status
                                if let Err(err) = self
                                    .core
                                    .storage
                                    .lookup
                                    .key_set(
                                        format!("oauth:{device_code}").into_bytes(),
                                        auth_code.serialize(),
                                        self.core.jmap.oauth_expiry_auth_code.into(),
                                    )
                                    .await
                                {
                                    return err.into_http_response();
                                }
                            }
                            Err(err) => return err.into_http_response(),
                            _ => (),
                        }

                        json!({
                            "data": success,
                        })
                    }
                };

                JsonResponse::new(response).into_http_response()
            }
            Err(err) => err.into_http_response(),
        }
    }

    pub async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        base_url: impl AsRef<str>,
    ) -> HttpResponse {
        // Parse form
        let client_id = match FormData::from_request(req, MAX_POST_LEN)
            .await
            .map(|mut p| p.remove("client_id"))
        {
            Ok(Some(client_id)) if client_id.len() < CLIENT_ID_MAX_LEN => client_id,
            Err(err) => return err,
            _ => {
                return HtmlResponse::with_status(
                    StatusCode::BAD_REQUEST,
                    "Client ID is invalid.".to_string(),
                )
                .into_http_response();
            }
        };

        // Generate device code
        let device_code = thread_rng()
            .sample_iter(Alphanumeric)
            .take(DEVICE_CODE_LEN)
            .map(char::from)
            .collect::<String>();

        // Generate user code
        let mut user_code = String::with_capacity(USER_CODE_LEN + 1);
        for (pos, ch) in thread_rng()
            .sample_iter::<usize, _>(Standard)
            .take(USER_CODE_LEN)
            .map(|v| char::from(USER_CODE_ALPHABET[v % USER_CODE_ALPHABET.len()]))
            .enumerate()
        {
            if pos == USER_CODE_LEN / 2 {
                user_code.push('-');
            }
            user_code.push(ch);
        }

        // Add OAuth status
        let oauth_code = Bincode::new(OAuthCode {
            status: OAuthStatus::Pending,
            account_id: u32::MAX,
            client_id,
            params: device_code.clone(),
        })
        .serialize();

        // Insert device code
        if let Err(err) = self
            .core
            .storage
            .lookup
            .key_set(
                format!("oauth:{device_code}").into_bytes(),
                oauth_code.clone(),
                self.core.jmap.oauth_expiry_user_code.into(),
            )
            .await
        {
            return err.into_http_response();
        }

        // Insert user code
        if let Err(err) = self
            .core
            .storage
            .lookup
            .key_set(
                format!("oauth:{user_code}").into_bytes(),
                oauth_code,
                self.core.jmap.oauth_expiry_user_code.into(),
            )
            .await
        {
            return err.into_http_response();
        }

        // Build response
        let base_url = base_url.as_ref();
        JsonResponse::new(DeviceAuthResponse {
            verification_uri: format!("{}/authorize", base_url),
            verification_uri_complete: format!("{}/authorize/?code={}", base_url, user_code),
            device_code,
            user_code,
            expires_in: self.core.jmap.oauth_expiry_user_code,
            interval: 5,
        })
        .into_http_response()
    }
}
