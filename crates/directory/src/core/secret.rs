/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use mail_builder::encoders::base64::base64_encode;
use mail_parser::decoders::base64::base64_decode;
use password_hash::PasswordHash;
use pbkdf2::Pbkdf2;
use pwhash::{bcrypt, bsdi_crypt, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
use scrypt::Scrypt;
use sha1::Digest;
use sha1::Sha1;
use sha2::Sha256;
use sha2::Sha512;
use tokio::sync::oneshot;
use totp_rs::TOTP;

use crate::backend::internal::SpecialSecrets;
use crate::DirectoryError;
use crate::Principal;

impl<T: serde::Serialize + serde::de::DeserializeOwned> Principal<T> {
    pub async fn verify_secret(&self, mut code: &str) -> crate::Result<bool> {
        let mut totp_token = None;
        let mut is_totp_token_missing = false;
        let mut is_totp_required = false;
        let mut is_totp_verified = false;
        let mut is_authenticated = false;
        let mut is_app_authenticated = false;

        for secret in &self.secrets {
            if secret.is_disabled() {
                // Account is disabled, no need to check further

                return Ok(false);
            } else if secret.is_otp_auth() {
                if !is_totp_verified && !is_totp_token_missing {
                    is_totp_required = true;

                    let totp_token = if let Some(totp_token) = totp_token {
                        totp_token
                    } else if let Some((_code, _totp_token)) = code
                        .rsplit_once('$')
                        .filter(|(c, t)| !c.is_empty() && !t.is_empty())
                    {
                        totp_token = Some(_totp_token);
                        code = _code;
                        _totp_token
                    } else {
                        is_totp_token_missing = true;
                        continue;
                    };

                    // Token needs to validate with at least one of the TOTP secrets
                    is_totp_verified = TOTP::from_url(secret)
                        .map_err(DirectoryError::InvalidTotpUrl)?
                        .check_current(totp_token)
                        .unwrap_or(false);
                }
            } else if !is_authenticated && !is_app_authenticated {
                if let Some((_, app_secret)) =
                    secret.strip_prefix("$app$").and_then(|s| s.split_once('$'))
                {
                    is_app_authenticated = verify_secret_hash(app_secret, code).await;
                } else {
                    is_authenticated = verify_secret_hash(secret, code).await;
                }
            }
        }

        if is_authenticated {
            if !is_totp_required {
                // Authenticated without TOTP enabled

                Ok(true)
            } else if is_totp_token_missing {
                // Only let the client know if the TOTP code is missing
                // if the password is correct

                Err(DirectoryError::MissingTotpCode)
            } else {
                // Return the TOTP verification status

                Ok(is_totp_verified)
            }
        } else if is_app_authenticated {
            // App passwords do not require TOTP

            Ok(true)
        } else {
            if is_totp_verified {
                // TOTP URL appeared after password hash in secrets list
                for secret in &self.secrets {
                    if secret.is_password() && verify_secret_hash(secret, code).await {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
    }
}

async fn verify_hash_prefix(hashed_secret: &str, secret: &str) -> bool {
    if hashed_secret.starts_with("$argon2")
        || hashed_secret.starts_with("$pbkdf2")
        || hashed_secret.starts_with("$scrypt")
    {
        let (tx, rx) = oneshot::channel();
        let secret = secret.to_string();
        let hashed_secret = hashed_secret.to_string();

        tokio::task::spawn_blocking(move || match PasswordHash::new(&hashed_secret) {
            Ok(hash) => {
                tx.send(
                    hash.verify_password(&[&Argon2::default(), &Pbkdf2, &Scrypt], &secret)
                        .is_ok(),
                )
                .ok();
            }
            Err(_) => {
                tracing::warn!(
                    context = "directory",
                    event = "error",
                    hash = hashed_secret,
                    "Invalid password hash"
                );
                tx.send(false).ok();
            }
        });

        match rx.await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(context = "directory", event = "error", "Thread join error");
                false
            }
        }
    } else if hashed_secret.starts_with("$2") {
        // Blowfish crypt
        bcrypt::verify(secret, hashed_secret)
    } else if hashed_secret.starts_with("$6$") {
        // SHA-512 crypt
        sha512_crypt::verify(secret, hashed_secret)
    } else if hashed_secret.starts_with("$5$") {
        // SHA-256 crypt
        sha256_crypt::verify(secret, hashed_secret)
    } else if hashed_secret.starts_with("$sha1") {
        // SHA-1 crypt
        sha1_crypt::verify(secret, hashed_secret)
    } else if hashed_secret.starts_with("$1") {
        // MD5 based hash
        md5_crypt::verify(secret, hashed_secret)
    } else {
        // Unknown hash
        tracing::warn!(
            context = "directory",
            event = "error",
            hash = hashed_secret,
            "Invalid password hash"
        );
        false
    }
}

pub async fn verify_secret_hash(hashed_secret: &str, secret: &str) -> bool {
    if hashed_secret.starts_with('$') {
        verify_hash_prefix(hashed_secret, secret).await
    } else if hashed_secret.starts_with('_') {
        // Enhanced DES-based hash
        bsdi_crypt::verify(secret, hashed_secret)
    } else if let Some(hashed_secret) = hashed_secret.strip_prefix('{') {
        if let Some((algo, hashed_secret)) = hashed_secret.split_once('}') {
            match algo {
                "ARGON2" | "ARGON2I" | "ARGON2ID" | "PBKDF2" => {
                    verify_hash_prefix(hashed_secret, secret).await
                }
                "SHA" => {
                    // SHA-1
                    let mut hasher = Sha1::new();
                    hasher.update(secret.as_bytes());
                    String::from_utf8(base64_encode(&hasher.finalize()[..]).unwrap_or_default())
                        .unwrap()
                        == hashed_secret
                }
                "SSHA" => {
                    // Salted SHA-1
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..20).unwrap_or_default();
                    let salt = decoded.get(20..).unwrap_or_default();
                    let mut hasher = Sha1::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    &hasher.finalize()[..] == hash
                }
                "SHA256" => {
                    // Verify hash
                    let mut hasher = Sha256::new();
                    hasher.update(secret.as_bytes());
                    String::from_utf8(base64_encode(&hasher.finalize()[..]).unwrap_or_default())
                        .unwrap()
                        == hashed_secret
                }
                "SSHA256" => {
                    // Salted SHA-256
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..32).unwrap_or_default();
                    let salt = decoded.get(32..).unwrap_or_default();
                    let mut hasher = Sha256::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    &hasher.finalize()[..] == hash
                }
                "SHA512" => {
                    // SHA-512
                    let mut hasher = Sha512::new();
                    hasher.update(secret.as_bytes());
                    String::from_utf8(base64_encode(&hasher.finalize()[..]).unwrap_or_default())
                        .unwrap()
                        == hashed_secret
                }
                "SSHA512" => {
                    // Salted SHA-512
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..64).unwrap_or_default();
                    let salt = decoded.get(64..).unwrap_or_default();
                    let mut hasher = Sha512::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    &hasher.finalize()[..] == hash
                }
                "MD5" => {
                    // MD5
                    let digest = md5::compute(secret.as_bytes());
                    String::from_utf8(base64_encode(&digest[..]).unwrap_or_default()).unwrap()
                        == hashed_secret
                }
                "CRYPT" | "crypt" => {
                    if hashed_secret.starts_with('$') {
                        verify_hash_prefix(hashed_secret, secret).await
                    } else {
                        // Unix crypt
                        unix_crypt::verify(secret, hashed_secret)
                    }
                }
                "PLAIN" | "plain" | "CLEAR" | "clear" => hashed_secret == secret,
                _ => {
                    tracing::warn!(
                        context = "directory",
                        event = "error",
                        algorithm = algo,
                        "Unsupported password hash algorithm"
                    );
                    false
                }
            }
        } else {
            tracing::warn!(
                context = "directory",
                event = "error",
                hash = hashed_secret,
                "Invalid password hash"
            );
            false
        }
    } else {
        hashed_secret == secret
    }
}
