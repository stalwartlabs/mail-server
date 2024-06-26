/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is not open source software. It must not be modified or distributed without
 * explicit permission from Stalwart Labs Ltd.
 * Unauthorized use, modification, or distribution is strictly prohibited.
 */

/*
 * WARNING: TAMPERING WITH THIS CODE IS STRICTLY PROHIBITED
 * Any attempt to modify, bypass, or disable the license validation mechanism
 * constitutes a severe violation of the Stalwart Enterprise License Agreement.
 * Such actions may result in immediate termination of your license, legal action,
 * and substantial financial penalties. Stalwart Labs Ltd. actively monitors for
 * unauthorized modifications and will pursue all available legal remedies against
 * violators to the fullest extent of the law, including but not limited to claims
 * for copyright infringement, breach of contract, and fraud.
 */

use std::{
    fmt::{Display, Formatter},
    time::{Duration, SystemTime},
};

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

use base64::{engine::general_purpose::STANDARD, Engine};

pub struct LicenseValidator {
    public_key: UnparsedPublicKey<Vec<u8>>,
}

pub struct LicenseGenerator {
    key_pair: Ed25519KeyPair,
}

#[derive(Debug, Clone)]
pub struct LicenseKey {
    pub valid_to: u64,
    pub valid_from: u64,
    pub hostname: String,
    pub accounts: u32,
}

#[derive(Debug)]
pub enum LicenseError {
    Expired,
    HostnameMismatch { issued_to: String, current: String },
    Parse,
    Validation,
    Decode,
    InvalidParameters,
}

const U64_LEN: usize = std::mem::size_of::<u64>();
const U32_LEN: usize = std::mem::size_of::<u32>();

impl LicenseValidator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        LicenseValidator {
            public_key: UnparsedPublicKey::new(
                &ED25519,
                vec![
                    118, 10, 182, 35, 89, 111, 11, 60, 154, 47, 205, 127, 107, 229, 55, 104, 72,
                    54, 141, 14, 97, 219, 2, 4, 119, 143, 156, 10, 152, 216, 32, 194,
                ],
            ),
        }
    }

    pub fn try_parse(&self, key: impl AsRef<str>) -> Result<LicenseKey, LicenseError> {
        let key = STANDARD
            .decode(key.as_ref())
            .map_err(|_| LicenseError::Decode)?;
        let valid_from = u64::from_le_bytes(
            key.get(..U64_LEN)
                .ok_or(LicenseError::Parse)?
                .try_into()
                .unwrap(),
        );
        let valid_to = u64::from_le_bytes(
            key.get(U64_LEN..(U64_LEN * 2))
                .ok_or(LicenseError::Parse)?
                .try_into()
                .unwrap(),
        );
        let accounts = u32::from_le_bytes(
            key.get((U64_LEN * 2)..(U64_LEN * 2) + U32_LEN)
                .ok_or(LicenseError::Parse)?
                .try_into()
                .unwrap(),
        );
        let hostname_len = u32::from_le_bytes(
            key.get((U64_LEN * 2) + U32_LEN..(U64_LEN * 2) + (U32_LEN * 2))
                .ok_or(LicenseError::Parse)?
                .try_into()
                .unwrap(),
        ) as usize;
        let hostname = String::from_utf8(
            key.get((U64_LEN * 2) + (U32_LEN * 2)..(U64_LEN * 2) + (U32_LEN * 2) + hostname_len)
                .ok_or(LicenseError::Parse)?
                .to_vec(),
        )
        .map_err(|_| LicenseError::Parse)?;
        let signature = key
            .get((U64_LEN * 2) + (U32_LEN * 2) + hostname_len..)
            .ok_or(LicenseError::Parse)?;

        if valid_from == 0
            || valid_to == 0
            || valid_from >= valid_to
            || accounts == 0
            || hostname.is_empty()
        {
            return Err(LicenseError::InvalidParameters);
        }

        // Validate signature
        self.public_key
            .verify(
                &key[..(U64_LEN * 2) + (U32_LEN * 2) + hostname_len],
                signature,
            )
            .map_err(|_| LicenseError::Validation)?;

        let key = LicenseKey {
            valid_from,
            valid_to,
            hostname,
            accounts,
        };

        if !key.is_expired() {
            Ok(key)
        } else {
            Err(LicenseError::Expired)
        }
    }
}

impl LicenseKey {
    pub fn new(hostname: String, accounts: u32, expires_in: u64) -> Self {
        let now = SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        LicenseKey {
            valid_from: now - 300,
            valid_to: now + expires_in + 300,
            hostname,
            accounts,
        }
    }

    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(
            self.valid_to.saturating_sub(
                SystemTime::UNIX_EPOCH
                    .elapsed()
                    .unwrap_or_default()
                    .as_secs(),
            ),
        )
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        now >= self.valid_to || now < self.valid_from
    }

    pub fn into_validated_key(self, hostname: impl AsRef<str>) -> Result<Self, LicenseError> {
        if self.hostname != hostname.as_ref() {
            Err(LicenseError::HostnameMismatch {
                issued_to: self.hostname.clone(),
                current: hostname.as_ref().to_string(),
            })
        } else {
            Ok(self)
        }
    }
}

impl LicenseGenerator {
    pub fn new(pkcs8_der: impl AsRef<[u8]>) -> Self {
        Self {
            key_pair: Ed25519KeyPair::from_pkcs8(pkcs8_der.as_ref()).unwrap(),
        }
    }

    pub fn generate(&self, key: LicenseKey) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&key.valid_from.to_le_bytes());
        bytes.extend_from_slice(&key.valid_to.to_le_bytes());
        bytes.extend_from_slice(&key.accounts.to_le_bytes());
        bytes.extend_from_slice(&(key.hostname.len() as u32).to_le_bytes());
        bytes.extend_from_slice(key.hostname.as_bytes());
        bytes.extend_from_slice(self.key_pair.sign(&bytes).as_ref());
        STANDARD.encode(&bytes)
    }
}

impl Display for LicenseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Expired => write!(f, "License is expired"),
            LicenseError::Parse => write!(f, "Failed to parse license key"),
            LicenseError::Validation => write!(f, "Failed to validate license key"),
            LicenseError::Decode => write!(f, "Failed to decode license key"),
            LicenseError::InvalidParameters => write!(f, "Invalid license key parameters"),
            LicenseError::HostnameMismatch { issued_to, current } => {
                write!(
                    f,
                    "License issued to {} does not match {}",
                    issued_to, current
                )
            }
        }
    }
}

/*

use rustls::sign::CertifiedKey;
use webpki::TrustAnchor;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};


fn validate_certificate(key: &CertifiedKey) -> Result<(), Box<dyn std::error::Error>> {
    let cert_der = key.end_entity_cert()?.as_ref();

    webpki::EndEntityCert::try_from(cert_der)?.verify_is_valid_tls_server_cert(
        &[
            &webpki::ECDSA_P256_SHA256,
            &webpki::ECDSA_P256_SHA384,
            &webpki::ECDSA_P384_SHA256,
            &webpki::ECDSA_P384_SHA384,
            &webpki::ED25519,
            &webpki::RSA_PKCS1_2048_8192_SHA256,
            &webpki::RSA_PKCS1_2048_8192_SHA384,
            &webpki::RSA_PKCS1_2048_8192_SHA512,
            &webpki::RSA_PKCS1_3072_8192_SHA384,
            &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ],
        &webpki::TlsServerTrustAnchors(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| TrustAnchor {
                    subject: ta.subject.as_ref(),
                    spki: ta.subject_public_key_info.as_ref(),
                    name_constraints: ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
                })
                .collect::<Vec<_>>()
                .as_slice(),
        ),
        &key.cert
            .iter()
            .skip(1)
            .map(|der| der.as_ref())
            .collect::<Vec<_>>(),
        webpki::Time::try_from(SystemTime::now())?,
    )?;

    // Additional checks
    let x509 = X509Certificate::from_der(cert_der)?.1;

    // Check if self-signed
    if x509.issuer() == x509.subject() {
        return Err("Certificate is self-signed".into());
    }

    // Check expiration
    let not_before = x509.validity().not_before.timestamp();
    let not_after = x509.validity().not_after.timestamp();
    let now = SystemTime::UNIX_EPOCH
        .elapsed()
        .unwrap_or_default()
        .as_secs() as i64;

    if now < not_before || now > not_after {
        Err("Certificate is expired or not yet valid".into())
    } else {
        Ok(())
    }
}


*/
