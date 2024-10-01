/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use utils::map::vec_map::VecMap;

use crate::api::{http::fetch_body, HttpRequest};

pub mod auth;
pub mod openid;
pub mod registration;
pub mod token;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OAuthStatus {
    Authorized,
    TokenIssued,
    Pending,
}

const MAX_POST_LEN: usize = 2048;

pub struct OAuth {
    pub key: String,
    pub expiry_user_code: u64,
    pub expiry_auth_code: u64,
    pub expiry_token: u64,
    pub expiry_refresh_token: u64,
    pub expiry_refresh_token_renew: u64,
    pub max_auth_attempts: u32,
    pub metadata: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCode {
    pub status: OAuthStatus,
    pub account_id: u32,
    pub client_id: String,
    pub params: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthGet {
    code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthPost {
    code: Option<String>,
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthRequest {
    client_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeAuthRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeAuthForm {
    code: String,
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub device_code: Option<String>,
    pub client_id: Option<String>,
    pub refresh_token: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenResponse {
    Granted(OAuthResponse),
    Error { error: ErrorType },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorType {
    #[serde(rename = "invalid_grant")]
    InvalidGrant,
    #[serde(rename = "invalid_client")]
    InvalidClient,
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,
    #[serde(rename = "authorization_pending")]
    AuthorizationPending,
    #[serde(rename = "slow_down")]
    SlowDown,
    #[serde(rename = "access_denied")]
    AccessDenied,
    #[serde(rename = "expired_token")]
    ExpiredToken,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OAuthCodeRequest {
    Code {
        client_id: String,
        redirect_uri: Option<String>,
    },
    Device {
        code: String,
    },
}

impl TokenResponse {
    pub fn error(error: ErrorType) -> Self {
        TokenResponse::Error { error }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, TokenResponse::Error { .. })
    }
}

#[derive(Debug)]
pub struct FormData {
    fields: VecMap<String, String>,
}

impl FormData {
    pub async fn from_request(
        req: &mut HttpRequest,
        max_len: usize,
        session_id: u64,
    ) -> trc::Result<Self> {
        match (
            req.headers()
                .get(CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .and_then(|val| val.parse::<mime::Mime>().ok()),
            fetch_body(req, max_len, session_id).await,
        ) {
            (Some(content_type), Some(body)) => {
                let mut fields = VecMap::new();
                if let Some(boundary) = content_type.get_param(mime::BOUNDARY) {
                    for mut field in
                        form_data::FormData::new(&body[..], boundary.as_str()).flatten()
                    {
                        let value = String::from_utf8_lossy(&field.bytes().unwrap_or_default())
                            .into_owned();
                        fields.append(field.name, value);
                    }
                } else {
                    for (key, value) in form_urlencoded::parse(&body) {
                        fields.append(key.into_owned(), value.into_owned());
                    }
                }
                Ok(FormData { fields })
            }
            _ => Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("Invalid post request")),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|v| v.as_str())
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.fields.remove(key)
    }

    pub fn has_field(&self, key: &str) -> bool {
        self.fields.get(key).map_or(false, |v| !v.is_empty())
    }

    pub fn fields(&self) -> impl Iterator<Item = (&String, &String)> {
        self.fields.iter()
    }
}
