/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use common::config::smtp::auth::simple_pem_parse;
use hyper::Method;
use jmap_proto::error::request::RequestError;
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::generate::DkimKeyPair,
};
use mail_builder::encoders::base64::base64_encode;
use mail_parser::DateTime;
use pkcs8::Document;
use rsa::pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use store::write::now;

use crate::{
    api::{
        http::ToHttpResponse, management::ManagementApiError, HttpRequest, HttpResponse,
        JsonResponse,
    },
    JMAP,
};

use super::decode_path_element;

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub enum Algorithm {
    Rsa,
    Ed25519,
}

#[derive(Debug, Serialize, Deserialize)]
struct DkimSignature {
    id: Option<String>,
    algorithm: Algorithm,
    domain: String,
    selector: Option<String>,
}

impl JMAP {
    pub async fn handle_manage_dkim(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
    ) -> HttpResponse {
        match *req.method() {
            Method::GET => self.handle_get_public_key(path).await,
            Method::POST => self.handle_create_signature(body).await,
            _ => RequestError::not_found().into_http_response(),
        }
    }

    async fn handle_get_public_key(&self, path: Vec<&str>) -> HttpResponse {
        let signature_id = match path.get(1) {
            Some(signature_id) => decode_path_element(signature_id),
            None => {
                return RequestError::not_found().into_http_response();
            }
        };

        let (pk, algo) = match (
            self.core
                .storage
                .config
                .get(&format!("signature.{signature_id}.private-key"))
                .await,
            self.core
                .storage
                .config
                .get(&format!("signature.{signature_id}.algorithm"))
                .await
                .map(|algo| algo.and_then(|algo| algo.parse::<Algorithm>().ok())),
        ) {
            (Ok(Some(pk)), Ok(Some(algorithm))) => (pk, algorithm),
            (Err(err), _) | (_, Err(err)) => return err.into_http_response(),
            _ => return RequestError::not_found().into_http_response(),
        };

        match obtain_dkim_public_key(algo, &pk) {
            Ok(data) => JsonResponse::new(json!({
                "data": data,
            }))
            .into_http_response(),
            Err(err) => ManagementApiError::Other {
                details: err.into(),
            }
            .into_http_response(),
        }
    }

    async fn handle_create_signature(&self, body: Option<Vec<u8>>) -> HttpResponse {
        let request =
            match serde_json::from_slice::<DkimSignature>(body.as_deref().unwrap_or_default()) {
                Ok(request) => request,
                Err(err) => return err.into_http_response(),
            };

        let algo_str = match request.algorithm {
            Algorithm::Rsa => "rsa",
            Algorithm::Ed25519 => "ed25519",
        };
        let id = request
            .id
            .unwrap_or_else(|| format!("{algo_str}-{}", request.domain));
        let selector = request.selector.unwrap_or_else(|| {
            let dt = DateTime::from_timestamp(now() as i64);
            format!(
                "{:04}{:02}{}",
                dt.year,
                dt.month,
                if Algorithm::Rsa == request.algorithm {
                    "r"
                } else {
                    "e"
                }
            )
        });

        // Make sure the signature does not exist already
        match self
            .core
            .storage
            .config
            .get(&format!("signature.{id}.private-key"))
            .await
        {
            Ok(None) => (),
            Ok(Some(value)) => {
                return ManagementApiError::FieldAlreadyExists {
                    field: format!("signature.{id}.private-key").into(),
                    value: value.into(),
                }
                .into_http_response();
            }
            Err(err) => return err.into_http_response(),
        }

        // Create signature
        match self
            .create_dkim_key(request.algorithm, id, request.domain, selector)
            .await
        {
            Ok(_) => JsonResponse::new(json!({
                "data": (),
            }))
            .into_http_response(),
            Err(err) => err.into_http_response(),
        }
    }

    async fn create_dkim_key(
        &self,
        algo: Algorithm,
        id: impl AsRef<str>,
        domain: impl Into<String>,
        selector: impl Into<String>,
    ) -> store::Result<()> {
        let id = id.as_ref();
        let (algorithm, pk_type) = match algo {
            Algorithm::Rsa => ("rsa-sha256", "RSA PRIVATE KEY"),
            Algorithm::Ed25519 => ("ed25519-sha256", "PRIVATE KEY"),
        };
        let mut pk = format!("-----BEGIN {pk_type}-----\n").into_bytes();
        let mut lf_count = 65;
        for ch in base64_encode(
            match algo {
                Algorithm::Rsa => DkimKeyPair::generate_rsa(2048),
                Algorithm::Ed25519 => DkimKeyPair::generate_ed25519(),
            }
            .map_err(|err| store::Error::InternalError(err.to_string()))?
            .private_key(),
        )
        .unwrap_or_default()
        {
            pk.push(ch);
            lf_count -= 1;
            if lf_count == 0 {
                pk.push(b'\n');
                lf_count = 65;
            }
        }
        if lf_count != 65 {
            pk.push(b'\n');
        }
        pk.extend_from_slice(format!("-----END {pk_type}-----\n").as_bytes());

        self.core
            .storage
            .config
            .set([
                (
                    format!("signature.{id}.private-key"),
                    String::from_utf8(pk).unwrap(),
                ),
                (format!("signature.{id}.domain"), domain.into()),
                (format!("signature.{id}.selector"), selector.into()),
                (format!("signature.{id}.algorithm"), algorithm.to_string()),
                (
                    format!("signature.{id}.canonicalization"),
                    "relaxed/relaxed".to_string(),
                ),
                (format!("signature.{id}.headers.0"), "From".to_string()),
                (format!("signature.{id}.headers.1"), "To".to_string()),
                (format!("signature.{id}.headers.2"), "Date".to_string()),
                (format!("signature.{id}.headers.3"), "Subject".to_string()),
                (
                    format!("signature.{id}.headers.4"),
                    "Message-ID".to_string(),
                ),
                (format!("signature.{id}.report"), "false".to_string()),
            ])
            .await
    }
}

pub fn obtain_dkim_public_key(algo: Algorithm, pk: &str) -> Result<String, &'static str> {
    match simple_pem_parse(pk) {
        Some(der) => match algo {
            Algorithm::Rsa => match RsaKey::<Sha256>::from_der(&der).and_then(|key| {
                Document::from_pkcs1_der(&key.public_key())
                    .map_err(|err| mail_auth::Error::CryptoError(err.to_string()))
            }) {
                Ok(pk) => Ok(
                    String::from_utf8(base64_encode(pk.as_bytes()).unwrap_or_default())
                        .unwrap_or_default(),
                ),
                Err(err) => {
                    tracing::debug!("Failed to read RSA DER: {err}");

                    Err("Failed to read RSA DER")
                }
            },
            Algorithm::Ed25519 => {
                match Ed25519Key::from_pkcs8_maybe_unchecked_der(&der)
                    .map_err(|err| mail_auth::Error::CryptoError(err.to_string()))
                {
                    Ok(pk) => Ok(String::from_utf8(
                        base64_encode(&pk.public_key()).unwrap_or_default(),
                    )
                    .unwrap_or_default()),
                    Err(err) => {
                        tracing::debug!("Failed to read ED25519 DER: {err}");

                        Err("Failed to read ED25519 DER")
                    }
                }
            }
        },
        None => Err("Failed to decode private key"),
    }
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-').map(|(algo, _)| algo) {
            Some("rsa") => Ok(Algorithm::Rsa),
            Some("ed25519") => Ok(Algorithm::Ed25519),
            _ => Err(()),
        }
    }
}
