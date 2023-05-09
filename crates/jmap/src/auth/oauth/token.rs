use std::{sync::atomic, time::SystemTime};

use hyper::StatusCode;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use store::{blake3, rand::thread_rng};

use crate::{auth::SymmetricEncrypt, JMAP};

use super::{
    ErrorType, TokenResponse, CLIENT_ID_MAX_LEN, RANDOM_CODE_LEN, STATUS_AUTHORIZED,
    STATUS_PENDING, STATUS_TOKEN_ISSUED,
};

// Token endpoint
pub async fn handle_token_request<T>(
    core: web::Data<JMAPServer<T>>,
    params: web::Form<TokenRequest>,
) -> HttpResponse
where
    T: for<'x> Store<'x> + 'static,
{
    let mut response = TokenResponse::error(ErrorType::InvalidGrant);

    if params.grant_type.eq_ignore_ascii_case("authorization_code") {
        response = if let (Some(code), Some(client_id), Some(redirect_uri)) =
            (&params.code, &params.client_id, &params.redirect_uri)
        {
            if let Some(oauth) = core.oauth_codes.get(code) {
                if client_id != &oauth.client_id
                    || redirect_uri != oauth.redirect_uri.as_deref().unwrap_or("")
                {
                    TokenResponse::error(ErrorType::InvalidClient)
                } else if oauth.status.load(atomic::Ordering::Relaxed) == STATUS_AUTHORIZED
                    && oauth.expiry.elapsed().as_secs() < core.oauth.expiry_auth_code
                {
                    // Mark this token as issued
                    oauth
                        .status
                        .store(STATUS_TOKEN_ISSUED, atomic::Ordering::Relaxed);

                    // Issue token
                    core.issue_token(
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
    } else if params
        .grant_type
        .eq_ignore_ascii_case("urn:ietf:params:oauth:grant-type:device_code")
    {
        response = TokenResponse::error(ErrorType::ExpiredToken);

        if let (Some(oauth), Some(client_id)) = (
            params
                .device_code
                .as_ref()
                .and_then(|dc| core.oauth_codes.get(dc)),
            &params.client_id,
        ) {
            if &oauth.client_id != client_id {
                response = TokenResponse::error(ErrorType::InvalidClient);
            } else if oauth.expiry.elapsed().as_secs() < core.oauth.expiry_user_code {
                response = match oauth.status.load(atomic::Ordering::Relaxed) {
                    STATUS_AUTHORIZED => {
                        // Mark this token as issued
                        oauth
                            .status
                            .store(STATUS_TOKEN_ISSUED, atomic::Ordering::Relaxed);

                        // Issue token
                        core.issue_token(
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
                        if (STATUS_PENDING..STATUS_PENDING + core.oauth.max_auth_attempts)
                            .contains(&status) =>
                    {
                        TokenResponse::error(ErrorType::AuthorizationPending)
                    }
                    STATUS_TOKEN_ISSUED => TokenResponse::error(ErrorType::ExpiredToken),
                    _ => TokenResponse::error(ErrorType::AccessDenied),
                };
            }
        }
    } else if params.grant_type.eq_ignore_ascii_case("refresh_token") {
        if let Some(refresh_token) = &params.refresh_token {
            match core
                .validate_access_token("refresh_token", refresh_token)
                .await
            {
                Ok((account_id, client_id, time_left)) => {
                    // TODO: implement revoking client ids
                    response = core
                        .issue_token(
                            account_id,
                            &client_id,
                            time_left <= core.oauth.expiry_refresh_token_renew,
                        )
                        .await
                        .unwrap_or_else(|err| {
                            tracing::debug!("Failed to refresh OAuth token: {}", err);
                            TokenResponse::error(ErrorType::InvalidGrant)
                        });
                }
                Err(err) => {
                    tracing::debug!("Refresh token failed validation: {}", err);
                }
            }
        } else {
            response = TokenResponse::error(ErrorType::InvalidRequest);
        }
    }

    HttpResponse::build(if response.is_error() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    })
    .content_type("application/json")
    .body(serde_json::to_string(&response).unwrap_or_default())
}

impl JMAP {
    async fn issue_token(
        &self,
        account_id: u32,
        client_id: &str,
        with_refresh_token: bool,
    ) -> store::Result<TokenResponse> {
        let store = self.store.clone();
        let password_hash = self
            .spawn_worker(move || {
                // Make sure account still exits
                if let Some(secret_hash) = store.get_account_secret_hash(account_id)? {
                    Ok(secret_hash)
                } else {
                    Err(StoreError::DeserializeError(
                        "Account no longer exists".into(),
                    ))
                }
            })
            .await?;

        Ok(TokenResponse::Granted {
            access_token: self.encode_access_token(
                "access_token",
                account_id,
                &password_hash,
                client_id,
                self.oauth.expiry_token,
            )?,
            token_type: "bearer".to_string(),
            expires_in: self.oauth.expiry_token,
            refresh_token: if with_refresh_token {
                self.encode_access_token(
                    "refresh_token",
                    account_id,
                    &password_hash,
                    client_id,
                    self.oauth.expiry_refresh_token,
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
    ) -> store::Result<String> {
        // Build context
        if client_id.len() > CLIENT_ID_MAX_LEN {
            return Err(StoreError::DeserializeError("ClientId is too long".into()));
        }
        let key = self.oauth.key.clone();
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
            .map_err(StoreError::DeserializeError)?;
        token.push_leb128(account_id);
        token.push_leb128(expiry);
        token.extend_from_slice(client_id.as_bytes());

        Ok(String::from_utf8(base64_encode(&token).unwrap_or_default()).unwrap())
    }

    pub fn validate_access_token(
        &self,
        grant_type: &str,
        token: &str,
    ) -> Option<(u32, String, u64)> {
        // Base64 decode token
        let token = base64_decode(token.as_bytes())
            .ok_or_else(|| StoreError::DeserializeError("Failed to decode.".to_string()))?;
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
            .ok_or_else(|| StoreError::DeserializeError("Failed to decode token.".into()))?;

        // Validate expiration
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(946684800); // Jan 1, 2000
        if expiry <= now {
            return Err(StoreError::DeserializeError("Token expired.".into()));
        }

        // Optain password hash
        let store = self.store.clone();
        let password_hash = self
            .spawn_worker(move || store.get_account_secret_hash(account_id))
            .await?
            .ok_or_else(|| StoreError::DeserializeError("Account no longer exists".into()))?;

        // Build context
        let key = self.oauth.key.clone();
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
            .map_err(|e| StoreError::DeserializeError(format!("Failed to decrypt: {}", e)))?;

        // Success
        Ok((account_id, client_id, expiry - now))
    }
}
