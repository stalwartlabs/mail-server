/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use crate::Principal;

impl Principal {
    pub async fn verify_secret(&self, secret: &str) -> bool {
        for hashed_secret in &self.secrets {
            if verify_secret_hash(hashed_secret, secret).await {
                return true;
            }
        }
        false
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

async fn verify_secret_hash(hashed_secret: &str, secret: &str) -> bool {
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
