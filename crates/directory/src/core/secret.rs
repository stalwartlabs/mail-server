/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use argon2::Argon2;
use compact_str::ToCompactString;
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

use crate::Principal;
use crate::backend::internal::SpecialSecrets;

impl Principal {
    pub async fn verify_secret(&self, mut code: &str) -> trc::Result<bool> {
        let mut totp_token = None;
        let mut is_totp_token_missing = false;
        let mut is_totp_required = false;
        let mut is_totp_verified = false;
        let mut is_authenticated = false;
        let mut is_app_authenticated = false;

        for secret in self.secrets.iter() {
            if secret.is_otp_auth() {
                if !is_totp_verified && !is_totp_token_missing {
                    is_totp_required = true;

                    let totp_token = if let Some(totp_token) = totp_token {
                        totp_token
                    } else if let Some((_code, _totp_token)) =
                        code.rsplit_once('$').filter(|(c, t)| {
                            !c.is_empty()
                                && (6..=8).contains(&t.len())
                                && t.as_bytes().iter().all(|b| b.is_ascii_digit())
                        })
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
                        .map_err(|err| {
                            trc::AuthEvent::Error
                                .reason(err)
                                .details(secret.to_compact_string())
                        })?
                        .check_current(totp_token)
                        .unwrap_or(false);
                }
            } else if !is_authenticated && !is_app_authenticated {
                if let Some((_, app_secret)) =
                    secret.strip_prefix("$app$").and_then(|s| s.split_once('$'))
                {
                    is_app_authenticated = verify_secret_hash(app_secret, code).await?;
                } else {
                    is_authenticated = verify_secret_hash(secret, code).await?;
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

                Err(trc::AuthEvent::MissingTotp.into_err())
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
                    if secret.is_password() && verify_secret_hash(secret, code).await? {
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        }
    }
}

async fn verify_hash_prefix(hashed_secret: &str, secret: &str) -> trc::Result<bool> {
    if hashed_secret.starts_with("$argon2")
        || hashed_secret.starts_with("$pbkdf2")
        || hashed_secret.starts_with("$scrypt")
    {
        let (tx, rx) = oneshot::channel();
        let secret = secret.to_string();
        let hashed_secret = hashed_secret.to_string();

        tokio::task::spawn_blocking(move || match PasswordHash::new(&hashed_secret) {
            Ok(hash) => {
                tx.send(Ok(hash
                    .verify_password(&[&Argon2::default(), &Pbkdf2, &Scrypt], &secret)
                    .is_ok()))
                    .ok();
            }
            Err(err) => {
                tx.send(Err(trc::AuthEvent::Error
                    .reason(err)
                    .details(hashed_secret)))
                    .ok();
            }
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .caused_by(trc::location!())
                .reason(err)),
        }
    } else if hashed_secret.starts_with("$2") {
        // Blowfish crypt
        Ok(bcrypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$6$") {
        // SHA-512 crypt
        Ok(sha512_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$5$") {
        // SHA-256 crypt
        Ok(sha256_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$sha1") {
        // SHA-1 crypt
        Ok(sha1_crypt::verify(secret, hashed_secret))
    } else if hashed_secret.starts_with("$1") {
        // MD5 based hash
        Ok(md5_crypt::verify(secret, hashed_secret))
    } else {
        Err(trc::AuthEvent::Error
            .into_err()
            .details(hashed_secret.to_string()))
    }
}

/// Converts FreeIPA' Password hashing convention into something readable by Stalwart
/// Because the hash length isn't included, it is defined to 64.
///
/// # Arguments
///
/// * `algo`: The algorithm found between curly braces
/// * `hashed_secret`: The hashed secret (without the algorithm at the beginning)
///
/// returns: A more conventional hashed password
///
/// # Examples
///
/// ```
/// use directory::core::secret::hash_braces_converter;
/// let sanitized_hash = hash_braces_converter("PBKDF2-SHA256", "1000$azjfzojezoezjl$zeiezjpezpiezfpifezj");
///
/// assert_eq!("$pbkdf-sha256$i=1000,l=64$azjfzojezoezjl$zeiezjpezpiezfpifezj", sanitized_hash);
///
/// ```
///
/// ```
pub async fn hash_braces_converter(algo: &str, hashed_secret: &str) -> String {
    let simplified_hash;

    // Remove the trailing newline in base64
    if hashed_secret.ends_with("==") {
        simplified_hash = hashed_secret.strip_suffix("==").unwrap();
    } else { simplified_hash = hashed_secret; }

    // Get the iterator
    let Some((iterations,hashed_data)) = simplified_hash.split_once("$")
    else { return simplified_hash.to_string(); };

    // Reformat
    return format!("${}$i={},l=64${}", algo.to_ascii_lowercase().as_str(), iterations, hashed_data);
}

pub async fn verify_secret_hash(hashed_secret: &str, secret: &str) -> trc::Result<bool> {
    if hashed_secret.starts_with('$') {
        verify_hash_prefix(hashed_secret, secret).await
    } else if hashed_secret.starts_with('_') {
        // Enhanced DES-based hash
        Ok(bsdi_crypt::verify(secret, hashed_secret))
    } else if let Some(hashed_secret) = hashed_secret.strip_prefix('{') {
        if let Some((algo, hashed_secret)) = hashed_secret.split_once('}') {
            match algo {
                "ARGON2" | "ARGON2I" | "ARGON2ID" | "PBKDF2" | "PBKDF2-SHA256" | "PBKDF2-SHA512" => {
                    // Use a different behavior if the password hash is in a FreeIPA-like convention
                    if !hashed_secret.contains(",")
                        && hashed_secret.chars().filter(|&ch| ch == '$').count() == 2
                    {
                        let final_hash = hash_braces_converter(algo, hashed_secret).await;
                        verify_hash_prefix(final_hash.as_str(), secret).await
                    } else {
                        verify_hash_prefix(hashed_secret, secret).await
                    }
                }
                "SHA" => {
                    // SHA-1
                    let mut hasher = Sha1::new();
                    hasher.update(secret.as_bytes());
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA" => {
                    // Salted SHA-1
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..20).unwrap_or_default();
                    let salt = decoded.get(20..).unwrap_or_default();
                    let mut hasher = Sha1::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "SHA256" => {
                    // Verify hash
                    let mut hasher = Sha256::new();
                    hasher.update(secret.as_bytes());
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA256" => {
                    // Salted SHA-256
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..32).unwrap_or_default();
                    let salt = decoded.get(32..).unwrap_or_default();
                    let mut hasher = Sha256::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "SHA512" => {
                    // SHA-512
                    let mut hasher = Sha512::new();
                    hasher.update(secret.as_bytes());
                    Ok(
                        String::from_utf8(
                            base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                        )
                        .unwrap()
                            == hashed_secret,
                    )
                }
                "SSHA512" => {
                    // Salted SHA-512
                    let decoded = base64_decode(hashed_secret.as_bytes()).unwrap_or_default();
                    let hash = decoded.get(..64).unwrap_or_default();
                    let salt = decoded.get(64..).unwrap_or_default();
                    let mut hasher = Sha512::new();
                    hasher.update(secret.as_bytes());
                    hasher.update(salt);
                    Ok(&hasher.finalize()[..] == hash)
                }
                "MD5" => {
                    // MD5
                    let digest = md5::compute(secret.as_bytes());
                    Ok(
                        String::from_utf8(base64_encode(&digest[..]).unwrap_or_default()).unwrap()
                            == hashed_secret,
                    )
                }
                "CRYPT" | "crypt" => {
                    if hashed_secret.starts_with('$') {
                        verify_hash_prefix(hashed_secret, secret).await
                    } else {
                        // Unix crypt
                        Ok(unix_crypt::verify(secret, hashed_secret))
                    }
                }
                "PLAIN" | "plain" | "CLEAR" | "clear" => Ok(hashed_secret == secret),
                _ => Err(trc::AuthEvent::Error
                    .ctx(trc::Key::Reason, "Unsupported algorithm")
                    .details(hashed_secret.to_string())),
            }
        } else {
            Err(trc::AuthEvent::Error
                .into_err()
                .details(hashed_secret.to_string()))
        }
    } else if !hashed_secret.is_empty() {
        Ok(hashed_secret == secret)
    } else {
        Ok(false)
    }
}
