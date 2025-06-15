/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::SystemTime;

use directory::QueryBy;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use store::{
    blake3,
    rand::{Rng, rng},
};
use trc::AddContext;
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::Server;

use super::{CLIENT_ID_MAX_LEN, GrantType, RANDOM_CODE_LEN, crypto::SymmetricEncrypt};

pub struct TokenInfo {
    pub grant_type: GrantType,
    pub account_id: u32,
    pub client_id: String,
    pub expiry: u64,
    pub issued_at: u64,
    pub expires_in: u64,
}

const OAUTH_EPOCH: u64 = 946684800; // Jan 1, 2000

impl Server {
    pub async fn encode_access_token(
        &self,
        grant_type: GrantType,
        account_id: u32,
        client_id: &str,
        expiry_in: u64,
    ) -> trc::Result<String> {
        // Build context
        if client_id.len() > CLIENT_ID_MAX_LEN {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Client id too long"));
        }

        // Include password hash if expiration is over 1 hour
        let password_hash = if expiry_in > 3600 {
            self.password_hash(account_id)
                .await
                .caused_by(trc::location!())?
        } else {
            "".into()
        };

        let key = &self.core.oauth.oauth_key;
        let context = format!(
            "{} {} {} {}",
            grant_type.as_str(),
            client_id,
            account_id,
            password_hash
        );

        // Set expiration time
        let issued_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .saturating_sub(OAUTH_EPOCH); // Jan 1, 2000
        let expiry = issued_at + expiry_in;

        // Calculate nonce
        let mut hasher = blake3::Hasher::new();
        if !password_hash.is_empty() {
            hasher.update(password_hash.as_bytes());
        }
        hasher.update(grant_type.as_str().as_bytes());
        hasher.update(issued_at.to_be_bytes().as_slice());
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
            .encrypt(&rng().random::<[u8; RANDOM_CODE_LEN]>(), &nonce)
            .map_err(|_| {
                trc::AuthEvent::Error
                    .into_err()
                    .ctx(trc::Key::Reason, "Failed to encrypt token")
                    .caused_by(trc::location!())
            })?;
        token.push_leb128(account_id);
        token.push(grant_type.id());
        token.push_leb128(issued_at);
        token.push_leb128(expiry);
        token.extend_from_slice(client_id.as_bytes());

        Ok(String::from_utf8(base64_encode(&token).unwrap_or_default()).unwrap())
    }

    pub async fn validate_access_token(
        &self,
        expected_grant_type: Option<GrantType>,
        token_: &str,
    ) -> trc::Result<TokenInfo> {
        // Base64 decode token
        let token = base64_decode(token_.as_bytes()).ok_or_else(|| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, "Failed to decode token")
                .caused_by(trc::location!())
                .details(token_.to_string())
        })?;
        let (account_id, grant_type, issued_at, expiry, client_id) = token
            .get((RANDOM_CODE_LEN + SymmetricEncrypt::ENCRYPT_TAG_LEN)..)
            .and_then(|bytes| {
                let mut bytes = bytes.iter();
                (
                    bytes.next_leb128()?,
                    GrantType::from_id(bytes.next().copied()?)?,
                    bytes.next_leb128::<u64>()?,
                    bytes.next_leb128::<u64>()?,
                    bytes.copied().map(char::from).collect::<String>(),
                )
                    .into()
            })
            .ok_or_else(|| {
                trc::AuthEvent::Error
                    .into_err()
                    .ctx(trc::Key::Reason, "Failed to decode token")
                    .caused_by(trc::location!())
                    .details(token_.to_string())
            })?;

        // Validate expiration
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .saturating_sub(OAUTH_EPOCH); // Jan 1, 2000
        if expiry <= now || issued_at > now {
            return Err(trc::AuthEvent::TokenExpired.into_err());
        }

        // Validate grant type
        if expected_grant_type.is_some_and(|g| g != grant_type) {
            return Err(trc::AuthEvent::Error
                .into_err()
                .details("Invalid grant type"));
        }

        // Obtain password hash
        let password_hash = if expiry - issued_at > 3600 {
            self.password_hash(account_id)
                .await
                .map_err(|err| trc::AuthEvent::Error.into_err().ctx(trc::Key::Details, err))?
        } else {
            "".into()
        };

        // Build context
        let key = self.core.oauth.oauth_key.clone();
        let context = format!(
            "{} {} {} {}",
            grant_type.as_str(),
            client_id,
            account_id,
            password_hash
        );

        // Calculate nonce
        let mut hasher = blake3::Hasher::new();
        if !password_hash.is_empty() {
            hasher.update(password_hash.as_bytes());
        }
        hasher.update(grant_type.as_str().as_bytes());
        hasher.update(issued_at.to_be_bytes().as_slice());
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
            .map_err(|err| {
                trc::AuthEvent::Error
                    .into_err()
                    .ctx(trc::Key::Details, "Failed to decode token")
                    .caused_by(trc::location!())
                    .reason(err)
            })?;

        // Success
        Ok(TokenInfo {
            grant_type,
            account_id,
            client_id,
            expiry: expiry + OAUTH_EPOCH,
            issued_at: issued_at + OAUTH_EPOCH,
            expires_in: expiry - now,
        })
    }

    pub async fn password_hash(&self, account_id: u32) -> trc::Result<String> {
        if account_id != u32::MAX {
            self.core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| {
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Account no longer exists")
                })?
                .secrets
                .into_iter()
                .next()
                .ok_or(
                    trc::AuthEvent::Error
                        .into_err()
                        .details("Account does not contain secrets")
                        .caused_by(trc::location!()),
                )
        } else if let Some((_, secret)) = &self.core.jmap.fallback_admin {
            Ok(secret.into())
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details("Invalid account ID")
                .caused_by(trc::location!()))
        }
    }
}
