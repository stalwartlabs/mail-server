/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{sync::atomic, time::SystemTime};

use hyper::StatusCode;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use mail_send::mail_auth::common::lru::DnsCache;
use store::{
    blake3,
    rand::{thread_rng, Rng},
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    auth::SymmetricEncrypt,
    JMAP,
};

use super::{
    parse_form_data, ErrorType, TokenResponse, CLIENT_ID_MAX_LEN, RANDOM_CODE_LEN,
    STATUS_AUTHORIZED, STATUS_PENDING, STATUS_TOKEN_ISSUED,
};

impl JMAP {
    // Token endpoint
    pub async fn handle_token_request(&self, req: &mut HttpRequest) -> HttpResponse {
        // Parse form
        let params = match parse_form_data(req).await {
            Ok(params) => params,
            Err(err) => return err,
        };
        let grant_type = params
            .get("grant_type")
            .map(|s| s.as_str())
            .unwrap_or_default();

        let mut response = TokenResponse::error(ErrorType::InvalidGrant);

        if grant_type.eq_ignore_ascii_case("authorization_code") {
            response = if let (Some(code), Some(client_id), Some(redirect_uri)) = (
                params.get("code"),
                params.get("client_id"),
                params.get("redirect_uri"),
            ) {
                if let Some(oauth) = self.oauth_codes.get(code) {
                    if client_id != &oauth.client_id
                        || redirect_uri != oauth.redirect_uri.as_deref().unwrap_or("")
                    {
                        TokenResponse::error(ErrorType::InvalidClient)
                    } else if oauth.status.load(atomic::Ordering::Relaxed) == STATUS_AUTHORIZED {
                        // Mark this token as issued
                        oauth
                            .status
                            .store(STATUS_TOKEN_ISSUED, atomic::Ordering::Relaxed);

                        // Issue token
                        self.issue_token(
                            oauth.account_id.load(atomic::Ordering::Relaxed),
                            &oauth.client_id,
                            true,
                        )
                        .await
                        .unwrap_or_else(|err| {
                            tracing::error!("Failed to generate OAuth token: {}", err);
                            TokenResponse::error(ErrorType::InvalidRequest)
                        })
                    } else {
                        TokenResponse::error(ErrorType::InvalidGrant)
                    }
                } else {
                    TokenResponse::error(ErrorType::AccessDenied)
                }
            } else {
                TokenResponse::error(ErrorType::InvalidClient)
            };
        } else if grant_type.eq_ignore_ascii_case("urn:ietf:params:oauth:grant-type:device_code") {
            response = TokenResponse::error(ErrorType::ExpiredToken);

            if let (Some(oauth), Some(client_id)) = (
                params
                    .get("device_code")
                    .and_then(|dc| self.oauth_codes.get(dc)),
                params.get("client_id"),
            ) {
                response = if &oauth.client_id != client_id {
                    TokenResponse::error(ErrorType::InvalidClient)
                } else {
                    match oauth.status.load(atomic::Ordering::Relaxed) {
                        STATUS_AUTHORIZED => {
                            // Mark this token as issued
                            oauth
                                .status
                                .store(STATUS_TOKEN_ISSUED, atomic::Ordering::Relaxed);

                            // Issue token
                            self.issue_token(
                                oauth.account_id.load(atomic::Ordering::Relaxed),
                                &oauth.client_id,
                                true,
                            )
                            .await
                            .unwrap_or_else(|err| {
                                tracing::error!("Failed to generate OAuth token: {}", err);
                                TokenResponse::error(ErrorType::InvalidRequest)
                            })
                        }
                        status
                            if (STATUS_PENDING
                                ..STATUS_PENDING + self.config.oauth_max_auth_attempts)
                                .contains(&status) =>
                        {
                            TokenResponse::error(ErrorType::AuthorizationPending)
                        }
                        STATUS_TOKEN_ISSUED => TokenResponse::error(ErrorType::ExpiredToken),
                        _ => TokenResponse::error(ErrorType::AccessDenied),
                    }
                };
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
                            time_left <= self.config.oauth_expiry_refresh_token_renew,
                        )
                        .await
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

    async fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        with_refresh_token: bool,
    ) -> Result<TokenResponse, &'static str> {
        let password_hash = self
            .directory
            .principal_by_id(account_id)
            .await
            .map_err(|_| "Temporary lookup error")?
            .ok_or("Account no longer exists")?
            .secrets
            .into_iter()
            .next()
            .ok_or("Failed to obtain password hash")?;

        Ok(TokenResponse::Granted {
            access_token: self.encode_access_token(
                "access_token",
                account_id,
                &password_hash,
                client_id,
                self.config.oauth_expiry_token,
            )?,
            token_type: "bearer".to_string(),
            expires_in: self.config.oauth_expiry_token,
            refresh_token: if with_refresh_token {
                self.encode_access_token(
                    "refresh_token",
                    account_id,
                    &password_hash,
                    client_id,
                    self.config.oauth_expiry_refresh_token,
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
        let key = self.config.oauth_key.clone();
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

        // Optain password hash
        let password_hash = self
            .directory
            .principal_by_id(account_id)
            .await
            .map_err(|_| "Temporary lookup error")?
            .ok_or("Account no longer exists")?
            .secrets
            .into_iter()
            .next()
            .ok_or("Failed to obtain password hash")?;

        // Build context
        let key = self.config.oauth_key.clone();
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
