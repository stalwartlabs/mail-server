/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use biscuit::{
    jwa::{Algorithm, SignatureAlgorithm},
    jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, JWKSet, OctetKeyParameters, OctetKeyType, PublicKeyUse,
        RSAKeyParameters, RSAKeyType, JWK,
    },
    jws::Secret,
};
use ring::signature::{self, KeyPair};
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, RsaPublicKey};
use store::rand::{distributions::Alphanumeric, thread_rng, Rng};
use utils::config::Config;
use x509_parser::num_bigint::BigUint;

use crate::{
    config::{build_ecdsa_pem, build_rsa_keypair},
    manager::webadmin::Resource,
};

#[derive(Clone)]
pub struct OAuthConfig {
    pub oauth_key: String,
    pub oauth_expiry_user_code: u64,
    pub oauth_expiry_auth_code: u64,
    pub oauth_expiry_token: u64,
    pub oauth_expiry_refresh_token: u64,
    pub oauth_expiry_refresh_token_renew: u64,
    pub oauth_max_auth_attempts: u32,

    pub allow_anonymous_client_registration: bool,
    pub require_client_authentication: bool,

    pub oidc_expiry_id_token: u64,
    pub oidc_signing_secret: Secret,
    pub oidc_signature_algorithm: SignatureAlgorithm,
    pub oidc_jwks: Resource<Vec<u8>>,
}

impl OAuthConfig {
    pub fn parse(config: &mut Config) -> Self {
        let oidc_signature_algorithm = match config.value("oauth.oidc.signature-algorithm") {
            Some(alg) => match alg.to_uppercase().as_str() {
                "HS256" => SignatureAlgorithm::HS256,
                "HS384" => SignatureAlgorithm::HS384,
                "HS512" => SignatureAlgorithm::HS512,

                "RS256" => SignatureAlgorithm::RS256,
                "RS384" => SignatureAlgorithm::RS384,
                "RS512" => SignatureAlgorithm::RS512,

                "ES256" => SignatureAlgorithm::ES256,
                "ES384" => SignatureAlgorithm::ES384,

                "PS256" => SignatureAlgorithm::PS256,
                "PS384" => SignatureAlgorithm::PS384,
                "PS512" => SignatureAlgorithm::PS512,
                _ => {
                    config.new_parse_error(
                        "oauth.oidc.signature-algorithm",
                        format!("Invalid OIDC signature algorithm: {}", alg),
                    );
                    SignatureAlgorithm::HS256
                }
            },
            None => SignatureAlgorithm::HS256,
        };

        let rand_key = thread_rng()
            .sample_iter(Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>()
            .into_bytes();

        let (oidc_signing_secret, algorithm) = match oidc_signature_algorithm {
            SignatureAlgorithm::None
            | SignatureAlgorithm::HS256
            | SignatureAlgorithm::HS384
            | SignatureAlgorithm::HS512 => {
                let key = config
                    .value("oauth.oidc.signature-key")
                    .map(|s| s.to_string().into_bytes())
                    .unwrap_or(rand_key);

                (
                    Secret::Bytes(key.clone()),
                    AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: OctetKeyType::Octet,
                        value: key,
                    }),
                )
            }
            SignatureAlgorithm::RS256
            | SignatureAlgorithm::RS384
            | SignatureAlgorithm::RS512
            | SignatureAlgorithm::PS256
            | SignatureAlgorithm::PS384
            | SignatureAlgorithm::PS512 => parse_rsa_key(config).unwrap_or_else(|| {
                (
                    Secret::Bytes(rand_key.clone()),
                    AlgorithmParameters::OctetKey(OctetKeyParameters {
                        key_type: OctetKeyType::Octet,
                        value: rand_key,
                    }),
                )
            }),
            SignatureAlgorithm::ES256 | SignatureAlgorithm::ES384 | SignatureAlgorithm::ES512 => {
                parse_ecdsa_key(config, oidc_signature_algorithm).unwrap_or_else(|| {
                    (
                        Secret::Bytes(rand_key.clone()),
                        AlgorithmParameters::OctetKey(OctetKeyParameters {
                            key_type: OctetKeyType::Octet,
                            value: rand_key,
                        }),
                    )
                })
            }
        };

        let oidc_jwks = Resource {
            content_type: "application/json".into(),
            contents: serde_json::to_string(&JWKSet {
                keys: vec![JWK {
                    common: CommonParameters {
                        public_key_use: PublicKeyUse::Signature.into(),
                        algorithm: Algorithm::Signature(oidc_signature_algorithm).into(),
                        key_id: "default".to_string().into(),
                        ..Default::default()
                    },
                    algorithm,
                    additional: (),
                }],
            })
            .unwrap_or_default()
            .into_bytes(),
        };

        OAuthConfig {
            oauth_key: config
                .value("oauth.key")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    thread_rng()
                        .sample_iter(Alphanumeric)
                        .take(64)
                        .map(char::from)
                        .collect::<String>()
                }),
            oauth_expiry_user_code: config
                .property_or_default::<Duration>("oauth.expiry.user-code", "30m")
                .unwrap_or_else(|| Duration::from_secs(30 * 60))
                .as_secs(),
            oauth_expiry_auth_code: config
                .property_or_default::<Duration>("oauth.expiry.auth-code", "10m")
                .unwrap_or_else(|| Duration::from_secs(10 * 60))
                .as_secs(),
            oauth_expiry_token: config
                .property_or_default::<Duration>("oauth.expiry.token", "1h")
                .unwrap_or_else(|| Duration::from_secs(60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token", "30d")
                .unwrap_or_else(|| Duration::from_secs(30 * 24 * 60 * 60))
                .as_secs(),
            oauth_expiry_refresh_token_renew: config
                .property_or_default::<Duration>("oauth.expiry.refresh-token-renew", "4d")
                .unwrap_or_else(|| Duration::from_secs(4 * 24 * 60 * 60))
                .as_secs(),
            oauth_max_auth_attempts: config
                .property_or_default("oauth.auth.max-attempts", "3")
                .unwrap_or(10),
            oidc_expiry_id_token: config
                .property_or_default::<Duration>("oauth.oidc.expiry.id-token", "15m")
                .unwrap_or_else(|| Duration::from_secs(15 * 60))
                .as_secs(),
            allow_anonymous_client_registration: config
                .property_or_default("oauth.client-registration.anonymous", "false")
                .unwrap_or(false),
            require_client_authentication: config
                .property_or_default("oauth.client-registration.require", "false")
                .unwrap_or(true),
            oidc_signing_secret,
            oidc_signature_algorithm,
            oidc_jwks,
        }
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            oauth_key: Default::default(),
            oauth_expiry_user_code: Default::default(),
            oauth_expiry_auth_code: Default::default(),
            oauth_expiry_token: Default::default(),
            oauth_expiry_refresh_token: Default::default(),
            oauth_expiry_refresh_token_renew: Default::default(),
            oauth_max_auth_attempts: Default::default(),
            oidc_expiry_id_token: Default::default(),
            allow_anonymous_client_registration: Default::default(),
            require_client_authentication: Default::default(),
            oidc_signing_secret: Secret::Bytes("secret".to_string().into_bytes()),
            oidc_signature_algorithm: SignatureAlgorithm::HS256,
            oidc_jwks: Resource {
                content_type: "application/json".into(),
                contents: serde_json::to_string(&JWKSet::<()> { keys: vec![] })
                    .unwrap_or_default()
                    .into_bytes(),
            },
        }
    }
}

fn parse_rsa_key(config: &mut Config) -> Option<(Secret, AlgorithmParameters)> {
    let rsa_key_pair = match build_rsa_keypair(config.value_require("oauth.oidc.signature-key")?) {
        Ok(key) => key,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to build RSA key: {}", err),
            );
            return None;
        }
    };

    let rsa_public_key = match RsaPublicKey::from_pkcs1_der(rsa_key_pair.public_key().as_ref()) {
        Ok(key) => key,
        Err(err) => {
            config.new_build_error(
                "oauth.oidc.signature-key",
                format!("Failed to obtain RSA public key: {}", err),
            );
            return None;
        }
    };

    let rsa_key_params = RSAKeyParameters {
        key_type: RSAKeyType::RSA,
        n: BigUint::from_bytes_be(&rsa_public_key.n().to_bytes_be()),
        e: BigUint::from_bytes_be(&rsa_public_key.e().to_bytes_be()),
        ..Default::default()
    };

    (
        Secret::RsaKeyPair(rsa_key_pair.into()),
        AlgorithmParameters::RSA(rsa_key_params),
    )
        .into()
}

fn parse_ecdsa_key(
    config: &mut Config,
    oidc_signature_algorithm: SignatureAlgorithm,
) -> Option<(Secret, AlgorithmParameters)> {
    let (alg, curve) = match oidc_signature_algorithm {
        SignatureAlgorithm::ES256 => (
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            EllipticCurve::P256,
        ),
        SignatureAlgorithm::ES384 => (
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            EllipticCurve::P384,
        ),
        _ => unreachable!(),
    };

    let ecdsa_key_pair =
        match build_ecdsa_pem(alg, config.value_require("oauth.oidc.signature-key")?) {
            Ok(key) => key,
            Err(err) => {
                config.new_build_error(
                    "oauth.oidc.signature-key",
                    format!("Failed to build ECDSA key: {}", err),
                );
                return None;
            }
        };

    let ecdsa_public_key = ecdsa_key_pair.public_key().as_ref();

    let (x, y) = match oidc_signature_algorithm {
        SignatureAlgorithm::ES256 => {
            let points = match p256::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    config.new_build_error(
                        "oauth.oidc.signature-key",
                        format!("Failed to parse ECDSA key: {}", err),
                    );
                    return None;
                }
            };

            (
                points.x().map(|x| x.to_vec()).unwrap_or_default(),
                points.y().map(|y| y.to_vec()).unwrap_or_default(),
            )
        }
        SignatureAlgorithm::ES384 => {
            let points = match p384::EncodedPoint::from_bytes(ecdsa_public_key) {
                Ok(points) => points,
                Err(err) => {
                    config.new_build_error(
                        "oauth.oidc.signature-key",
                        format!("Failed to parse ECDSA key: {}", err),
                    );
                    return None;
                }
            };

            (
                points.x().map(|x| x.to_vec()).unwrap_or_default(),
                points.y().map(|y| y.to_vec()).unwrap_or_default(),
            )
        }
        _ => unreachable!(),
    };

    let ecdsa_key_params = EllipticCurveKeyParameters {
        key_type: EllipticCurveKeyType::EC,
        curve,
        x,
        y,
        d: None,
    };

    (
        Secret::EcdsaKeyPair(ecdsa_key_pair.into()),
        AlgorithmParameters::EllipticCurve(ecdsa_key_params),
    )
        .into()
}
