/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::SystemTime;

use directory::QueryBy;
use hyper::StatusCode;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use store::{
    blake3,
    rand::{thread_rng, Rng},
    write::Bincode,
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    auth::SymmetricEncrypt,
    JMAP,
};

use super::{
    ErrorType, FormData, OAuthCode, OAuthResponse, OAuthStatus, TokenResponse, CLIENT_ID_MAX_LEN,
    MAX_POST_LEN, RANDOM_CODE_LEN,
};

impl JMAP {
    // Token endpoint
    pub async fn handle_token_request(&self, req: &mut HttpRequest) -> HttpResponse {
        // Parse form
        let params = match FormData::from_request(req, MAX_POST_LEN).await {
            Ok(params) => params,
            Err(err) => return err,
        };
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
                    .await
                {
                    Ok(Some(auth_code)) => {
                        let oauth = auth_code.inner;
                        if client_id != oauth.client_id || redirect_uri != oauth.params {
                            TokenResponse::error(ErrorType::InvalidClient)
                        } else if oauth.status == OAuthStatus::Authorized {
                            // Mark this token as issued
                            if let Err(err) = self
                                .core
                                .storage
                                .lookup
                                .key_delete(format!("oauth:{code}").into_bytes())
                                .await
                            {
                                return err.into_http_response();
                            }

                            // Issue token
                            self.issue_token(oauth.account_id, &oauth.client_id, true)
                                .await
                                .map(TokenResponse::Granted)
                                .unwrap_or_else(|err| {
                                    tracing::error!("Failed to generate OAuth token: {}", err);
                                    TokenResponse::error(ErrorType::InvalidRequest)
                                })
                        } else {
                            TokenResponse::error(ErrorType::InvalidGrant)
                        }
                    }
                    Ok(None) => TokenResponse::error(ErrorType::AccessDenied),
                    Err(err) => return err.into_http_response(),
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
                match self
                    .core
                    .storage
                    .lookup
                    .key_get::<Bincode<OAuthCode>>(format!("oauth:{device_code}").into_bytes())
                    .await
                {
                    Ok(Some(auth_code)) => {
                        let oauth = auth_code.inner;
                        response = if oauth.client_id != client_id {
                            TokenResponse::error(ErrorType::InvalidClient)
                        } else {
                            match oauth.status {
                                OAuthStatus::Authorized => {
                                    // Mark this token as issued
                                    if let Err(err) = self
                                        .core
                                        .storage
                                        .lookup
                                        .key_delete(format!("oauth:{device_code}").into_bytes())
                                        .await
                                    {
                                        return err.into_http_response();
                                    }

                                    // Issue token
                                    self.issue_token(oauth.account_id, &oauth.client_id, true)
                                        .await
                                        .map(TokenResponse::Granted)
                                        .unwrap_or_else(|err| {
                                            tracing::error!(
                                                "Failed to generate OAuth token: {}",
                                                err
                                            );
                                            TokenResponse::error(ErrorType::InvalidRequest)
                                        })
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
                    Ok(None) => (),
                    Err(err) => return err.into_http_response(),
                }
            }
        } else if grant_type.eq_ignore_ascii_case("refresh_token") {
            if let Some(refresh_token) = params.get("refresh_token") {
                if let Ok((account_id, client_id, time_left)) = self
                    .validate_access_token("refresh_token", refresh_token)
                    .await
                {
                    // TODO: implement revoking client ids
                    response = self
                        .issue_token(
                            account_id,
                            &client_id,
                            time_left <= self.core.jmap.oauth_expiry_refresh_token_renew,
                        )
                        .await
                        .map(TokenResponse::Granted)
                        .unwrap_or_else(|err| {
                            tracing::debug!("Failed to refresh OAuth token: {}", err);
                            TokenResponse::error(ErrorType::InvalidGrant)
                        });
                }
            } else {
                response = TokenResponse::error(ErrorType::InvalidRequest);
            }
        }

        JsonResponse::with_status(
            if response.is_error() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            },
            response,
        )
        .into_http_response()
    }

    async fn password_hash(&self, account_id: u32) -> Result<String, &'static str> {
        if account_id != u32::MAX {
            self.core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .map_err(|_| "Temporary lookup error")?
                .ok_or("Account no longer exists")?
                .secrets
                .into_iter()
                .next()
                .ok_or("Failed to obtain password hash")
        } else if let Some((_, secret)) = &self.core.jmap.fallback_admin {
            Ok(secret.clone())
        } else {
            Err("Invalid account id.")
        }
    }

    pub async fn issue_token(
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

    fn encode_access_token(
        &self,
        grant_type: &str,
        account_id: u32,
        password_hash: &str,
        client_id: &str,
        expiry_in: u64,
    ) -> Result<String, &'static str> {
        // Build context
        if client_id.len() > CLIENT_ID_MAX_LEN {
            return Err("ClientId is too long");
        }
        let key = self.core.jmap.oauth_key.clone();
        let context = format!(
            "{} {} {} {}",
            grant_type, client_id, account_id, password_hash
        );
        let context_nonce = format!("{} nonce {}", grant_type, password_hash);

        // Set expiration time
        let expiry = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(946684800) // Jan 1, 2000
                + expiry_in;

        // Calculate nonce
        let mut hasher = blake3::Hasher::new();
        hasher.update(context_nonce.as_bytes());
        hasher.update(expiry.to_be_bytes().as_slice());
        let nonce = hasher
            .finalize()
            .as_bytes()
            .iter()
            .take(SymmetricEncrypt::NONCE_LEN)
            .copied()
            .collect::<Vec<_>>();

        // Encrypt random bytes
        let mut token = SymmetricEncrypt::new(key.as_bytes(), &context)
            .encrypt(&thread_rng().gen::<[u8; RANDOM_CODE_LEN]>(), &nonce)
            .map_err(|_| "Failed to encrypt token.")?;
        token.push_leb128(account_id);
        token.push_leb128(expiry);
        token.extend_from_slice(client_id.as_bytes());

        Ok(String::from_utf8(base64_encode(&token).unwrap_or_default()).unwrap())
    }

    pub async fn validate_access_token(
        &self,
        grant_type: &str,
        token: &str,
    ) -> Result<(u32, String, u64), &'static str> {
        // Base64 decode token
        let token = base64_decode(token.as_bytes()).ok_or("Failed to decode.")?;
        let (account_id, expiry, client_id) = token
            .get((RANDOM_CODE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN)..)
            .and_then(|bytes| {
                let mut bytes = bytes.iter();
                (
                    bytes.next_leb128()?,
                    bytes.next_leb128::<u64>()?,
                    bytes.copied().map(char::from).collect::<String>(),
                )
                    .into()
            })
            .ok_or("Failed to decode token.")?;

        // Validate expiration
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(946684800); // Jan 1, 2000
        if expiry <= now {
            return Err("Token expired.");
        }

        // Obtain password hash
        let password_hash = self.password_hash(account_id).await?;

        // Build context
        let key = self.core.jmap.oauth_key.clone();
        let context = format!(
            "{} {} {} {}",
            grant_type, client_id, account_id, password_hash
        );
        let context_nonce = format!("{} nonce {}", grant_type, password_hash);

        // Calculate nonce
        let mut hasher = blake3::Hasher::new();
        hasher.update(context_nonce.as_bytes());
        hasher.update(expiry.to_be_bytes().as_slice());
        let nonce = hasher
            .finalize()
            .as_bytes()
            .iter()
            .take(SymmetricEncrypt::NONCE_LEN)
            .copied()
            .collect::<Vec<_>>();

        // Decrypt
        SymmetricEncrypt::new(key.as_bytes(), &context)
            .decrypt(
                &token[..RANDOM_CODE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN],
                &nonce,
            )
            .map_err(|_| "Failed to decrypt token.")?;

        // Success
        Ok((account_id, client_id, expiry - now))
    }
}
