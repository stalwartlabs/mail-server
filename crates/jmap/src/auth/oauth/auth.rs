/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use rand::distributions::Standard;
use serde_json::json;
use store::{
    rand::{distributions::Alphanumeric, thread_rng, Rng},
    write::Bincode,
    Serialize,
};

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    auth::{oauth::OAuthStatus, AccessToken},
    JMAP,
};

use super::{
    DeviceAuthResponse, FormData, OAuthCode, OAuthCodeRequest, CLIENT_ID_MAX_LEN, DEVICE_CODE_LEN,
    MAX_POST_LEN, USER_CODE_ALPHABET, USER_CODE_LEN,
};

impl JMAP {
    pub async fn handle_oauth_api_request(
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
            } => {
                // Validate clientId
                if client_id.len() > CLIENT_ID_MAX_LEN {
                    return Err(trc::ManageEvent::Error
                        .into_err()
                        .details("Client ID is invalid."));
                } else if redirect_uri
                    .as_ref()
                    .map_or(false, |uri| !uri.starts_with("https://"))
                {
                    return Err(trc::ManageEvent::Error
                        .into_err()
                        .details("Redirect URI must be HTTPS."));
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
                self.core
                    .storage
                    .lookup
                    .key_set(
                        format!("oauth:{client_code}").into_bytes(),
                        value,
                        self.core.jmap.oauth_expiry_auth_code.into(),
                    )
                    .await?;

                #[cfg(not(feature = "enterprise"))]
                let is_enterprise = false;
                #[cfg(feature = "enterprise")]
                let is_enterprise = self.core.is_enterprise_edition();

                json!({
                    "data": {
                        "code": client_code,
                        "is_admin": access_token.is_super_user(),
                        "is_enterprise": is_enterprise,
                    },
                })
            }
            OAuthCodeRequest::Device { code } => {
                let mut success = false;

                // Obtain code
                if let Some(mut auth_code) = self
                    .core
                    .storage
                    .lookup
                    .key_get::<Bincode<OAuthCode>>(format!("oauth:{code}").into_bytes())
                    .await?
                {
                    if auth_code.inner.status == OAuthStatus::Pending {
                        auth_code.inner.status = OAuthStatus::Authorized;
                        auth_code.inner.account_id = access_token.primary_id();
                        let device_code = std::mem::take(&mut auth_code.inner.params);
                        success = true;

                        // Delete issued user code
                        self.core
                            .storage
                            .lookup
                            .key_delete(format!("oauth:{code}").into_bytes())
                            .await?;

                        // Update device code status
                        self.core
                            .storage
                            .lookup
                            .key_set(
                                format!("oauth:{device_code}").into_bytes(),
                                auth_code.serialize(),
                                self.core.jmap.oauth_expiry_auth_code.into(),
                            )
                            .await?;
                    }
                }

                json!({
                    "data": success,
                })
            }
        };

        Ok(JsonResponse::new(response).into_http_response())
    }

    pub async fn handle_device_auth(
        &self,
        req: &mut HttpRequest,
        base_url: impl AsRef<str>,
    ) -> trc::Result<HttpResponse> {
        // Parse form
        let client_id = FormData::from_request(req, MAX_POST_LEN)
            .await?
            .remove("client_id")
            .filter(|client_id| client_id.len() < CLIENT_ID_MAX_LEN)
            .ok_or_else(|| {
                trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("Client ID is missing.")
            })?;

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
        self.core
            .storage
            .lookup
            .key_set(
                format!("oauth:{device_code}").into_bytes(),
                oauth_code.clone(),
                self.core.jmap.oauth_expiry_user_code.into(),
            )
            .await?;

        // Insert user code
        self.core
            .storage
            .lookup
            .key_set(
                format!("oauth:{user_code}").into_bytes(),
                oauth_code,
                self.core.jmap.oauth_expiry_user_code.into(),
            )
            .await?;

        // Build response
        let base_url = base_url.as_ref();
        Ok(JsonResponse::new(DeviceAuthResponse {
            verification_uri: format!("{}/authorize", base_url),
            verification_uri_complete: format!("{}/authorize/?code={}", base_url, user_code),
            device_code,
            user_code,
            expires_in: self.core.jmap.oauth_expiry_user_code,
            interval: 5,
        })
        .into_http_response())
    }
}
