// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{Digest, SHA256, digest};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::Serialize;

pub(crate) fn sign(
    key: &EcdsaKeyPair,
    kid: Option<&str>,
    nonce: String,
    url: &str,
    payload: &str,
) -> trc::Result<String> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::encode("ES256", jwk, kid, nonce.into(), url)?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = key
        .sign(&SystemRandom::new(), combined.as_bytes())
        .map_err(|err| {
            trc::EventType::Acme(trc::AcmeEvent::Error)
                .caused_by(trc::location!())
                .reason(err)
        })?;

    serde_json::to_string(&Body {
        protected,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
    })
    .map_err(|err| trc::EventType::Acme(trc::AcmeEvent::Error).from_json_error(err))
}

pub(crate) fn eab_sign(
    key: &EcdsaKeyPair,
    kid: &str,
    hmac_key: &[u8],
    url: &str,
) -> trc::Result<Body> {
    let protected = Protected::encode("HS256", None, kid.into(), None, url)?;
    let payload = Jwk::new(key).base64()?;
    let combined = format!("{}.{}", &protected, &payload);

    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    let tag = hmac::sign(&key, combined.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(tag.as_ref());

    Ok(Body {
        protected,
        payload,
        signature,
    })
}

pub(crate) fn key_authorization(key: &EcdsaKeyPair, token: &str) -> trc::Result<String> {
    Ok(format!(
        "{}.{}",
        token,
        Jwk::new(key).thumb_sha256_base64()?
    ))
}

pub(crate) fn key_authorization_sha256(key: &EcdsaKeyPair, token: &str) -> trc::Result<Digest> {
    key_authorization(key, token).map(|s| digest(&SHA256, s.as_bytes()))
}

pub(crate) fn key_authorization_sha256_base64(
    key: &EcdsaKeyPair,
    token: &str,
) -> trc::Result<String> {
    key_authorization_sha256(key, token).map(|s| URL_SAFE_NO_PAD.encode(s.as_ref()))
}

#[derive(Debug, Serialize)]
pub(crate) struct Body {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn encode(
        alg: &'static str,
        jwk: Option<Jwk>,
        kid: Option<&'a str>,
        nonce: Option<String>,
        url: &'a str,
    ) -> trc::Result<String> {
        serde_json::to_vec(&Protected {
            alg,
            jwk,
            kid,
            nonce,
            url,
        })
        .map_err(|err| trc::EventType::Acme(trc::AcmeEvent::Error).from_json_error(err))
        .map(|v| URL_SAFE_NO_PAD.encode(v.as_slice()))
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }

    pub(crate) fn base64(&self) -> trc::Result<String> {
        serde_json::to_vec(self)
            .map_err(|err| trc::EventType::Acme(trc::AcmeEvent::Error).from_json_error(err))
            .map(|v| URL_SAFE_NO_PAD.encode(v.as_slice()))
    }

    pub(crate) fn thumb_sha256_base64(&self) -> trc::Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(digest(
            &SHA256,
            &serde_json::to_vec(&JwkThumb {
                crv: self.crv,
                kty: self.kty,
                x: &self.x,
                y: &self.y,
            })
            .map_err(|err| trc::EventType::Acme(trc::AcmeEvent::Error).from_json_error(err))?,
        )))
    }
}

#[derive(Serialize)]
struct JwkThumb<'a> {
    crv: &'a str,
    kty: &'a str,
    x: &'a str,
    y: &'a str,
}
