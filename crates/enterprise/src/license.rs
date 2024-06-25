/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SCL
 */

use std::time::SystemTime;

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

use base64::{engine::general_purpose::STANDARD, Engine};

pub struct LicenseValidator {
    pub public_key: UnparsedPublicKey<Vec<u8>>,
}

pub struct LicenseGenerator {
    key_pair: Ed25519KeyPair,
}

#[derive(Debug)]
pub struct LicenseKey {
    pub valid_to: u64,
    pub valid_from: u64,
    pub domain: String,
    pub accounts: u32,
}

#[derive(Debug)]
pub enum LicenseError {
    Expired,
    Parse,
    Validation,
    Decode,
    Invalid,
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

    pub fn validate(&self, key: impl AsRef<str>) -> Result<LicenseKey, LicenseError> {
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
        let domain_len = u32::from_le_bytes(
            key.get((U64_LEN * 2) + U32_LEN..(U64_LEN * 2) + (U32_LEN * 2))
                .ok_or(LicenseError::Parse)?
                .try_into()
                .unwrap(),
        ) as usize;
        let domain = String::from_utf8(
            key.get((U64_LEN * 2) + (U32_LEN * 2)..(U64_LEN * 2) + (U32_LEN * 2) + domain_len)
                .ok_or(LicenseError::Parse)?
                .to_vec(),
        )
        .map_err(|_| LicenseError::Parse)?;
        let signature = key
            .get((U64_LEN * 2) + (U32_LEN * 2) + domain_len..)
            .ok_or(LicenseError::Parse)?;

        if valid_from == 0
            || valid_to == 0
            || valid_from >= valid_to
            || accounts == 0
            || domain.is_empty()
        {
            return Err(LicenseError::Invalid);
        }

        // Validate signature
        self.public_key
            .verify(
                &key[..(U64_LEN * 2) + (U32_LEN * 2) + domain_len],
                signature,
            )
            .map_err(|_| LicenseError::Validation)?;

        let key = LicenseKey {
            valid_from,
            valid_to,
            domain,
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
    pub fn new(domain: String, accounts: u32, expires_in: u64) -> Self {
        let now = SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_secs();
        LicenseKey {
            valid_from: now - 300,
            valid_to: now + expires_in + 300,
            domain,
            accounts,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_secs();

        now >= self.valid_to || now < self.valid_from
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
        bytes.extend_from_slice(&(key.domain.len() as u32).to_le_bytes());
        bytes.extend_from_slice(key.domain.as_bytes());
        bytes.extend_from_slice(self.key_pair.sign(&bytes).as_ref());
        STANDARD.encode(&bytes)
    }
}
