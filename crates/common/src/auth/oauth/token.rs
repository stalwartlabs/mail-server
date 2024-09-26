/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::SystemTime;

use directory::{backend::internal::PrincipalField, QueryBy};
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use store::{
    blake3,
    rand::{thread_rng, Rng},
};
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

use crate::Server;

use super::{crypto::SymmetricEncrypt, CLIENT_ID_MAX_LEN, RANDOM_CODE_LEN};

impl Server {
    pub async fn issue_custom_token(
        &self,
        account_id: u32,
        grant_type: &str,
        client_id: &str,
        expiry_in: u64,
    ) -> trc::Result<String> {
        self.encode_access_token(
            grant_type,
            account_id,
            &self
                .password_hash(account_id)
                .await
                .map_err(|err| trc::StoreEvent::UnexpectedError.into_err().details(err))?,
            client_id,
            expiry_in,
        )
        .map_err(|err| trc::StoreEvent::UnexpectedError.into_err().details(err))
    }

    pub fn encode_access_token(
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
        token_: &str,
    ) -> trc::Result<(u32, String, u64)> {
        // Base64 decode token
        let token = base64_decode(token_.as_bytes()).ok_or_else(|| {
            trc::AuthEvent::Error
                .into_err()
                .ctx(trc::Key::Reason, "Failed to decode token")
                .caused_by(trc::location!())
                .details(token_.to_string())
        })?;
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
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(946684800); // Jan 1, 2000
        if expiry <= now {
            return Err(trc::AuthEvent::TokenExpired.into_err());
        }

        // Obtain password hash
        let password_hash = self
            .password_hash(account_id)
            .await
            .map_err(|err| trc::AuthEvent::Error.into_err().ctx(trc::Key::Details, err))?;

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
            .map_err(|err| {
                trc::AuthEvent::Error
                    .into_err()
                    .ctx(trc::Key::Details, "Failed to decode token")
                    .caused_by(trc::location!())
                    .reason(err)
            })?;

        // Success
        Ok((account_id, client_id, expiry - now))
    }

    pub async fn password_hash(&self, account_id: u32) -> Result<String, &'static str> {
        if account_id != u32::MAX {
            self.core
                .storage
                .directory
                .query(QueryBy::Id(account_id), false)
                .await
                .map_err(|_| "Temporary lookup error")?
                .ok_or("Account no longer exists")?
                .take_str_array(PrincipalField::Secrets)
                .unwrap_or_default()
                .into_iter()
                .next()
                .ok_or("Failed to obtain password hash")
        } else if let Some((_, secret)) = &self.core.jmap.fallback_admin {
            Ok(secret.clone())
        } else {
            Err("Invalid account id.")
        }
    }
}
