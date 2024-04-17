// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rcgen::{Certificate, CustomExtension, PKCS_ECDSA_P256_SHA256};
use reqwest::header::{ToStrError, CONTENT_TYPE};
use reqwest::{Method, Response, StatusCode};
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use serde_json::json;
use store::write::Bincode;
use store::Serialize;

use super::jose::{
    key_authorization, key_authorization_sha256, key_authorization_sha256_base64, sign, JoseError,
};

pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub kid: String,
}

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

impl Account {
    pub fn generate_key_pair() -> Vec<u8> {
        EcdsaKeyPair::generate_pkcs8(ALG, &SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub async fn create<'a, S, I>(directory: Directory, contact: I) -> Result<Self, DirectoryError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        Self::create_with_keypair(directory, contact, &Self::generate_key_pair()).await
    }

    pub async fn create_with_keypair<'a, S, I>(
        directory: Directory,
        contact: I,
        key_pair: &[u8],
    ) -> Result<Self, DirectoryError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let key_pair = EcdsaKeyPair::from_pkcs8(ALG, key_pair, &SystemRandom::new())?;
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": contact,
        })
        .to_string();
        let body = sign(
            &key_pair,
            None,
            directory.nonce().await?,
            &directory.new_account,
            &payload,
        )?;
        let response = https(&directory.new_account, Method::POST, Some(body)).await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
        })
    }

    async fn request(
        &self,
        url: impl AsRef<str>,
        payload: &str,
    ) -> Result<(Option<String>, String), DirectoryError> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce().await?,
            url.as_ref(),
            payload,
        )?;
        let response = https(url.as_ref(), Method::POST, Some(body)).await?;
        let location = get_header(&response, "Location").ok();
        let body = response.text().await?;
        Ok((location, body))
    }

    pub async fn new_order(&self, domains: Vec<String>) -> Result<(String, Order), DirectoryError> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let response = self.request(&self.directory.new_order, &payload).await?;
        let url = response
            .0
            .ok_or(DirectoryError::MissingHeader("Location"))?;
        let order = serde_json::from_str(&response.1)?;
        Ok((url, order))
    }

    pub async fn auth(&self, url: impl AsRef<str>) -> Result<Auth, DirectoryError> {
        let response = self.request(url, "").await?;
        serde_json::from_str(&response.1).map_err(Into::into)
    }

    pub async fn challenge(&self, url: impl AsRef<str>) -> Result<(), DirectoryError> {
        self.request(&url, "{}").await.map(|_| ())
    }

    pub async fn order(&self, url: impl AsRef<str>) -> Result<Order, DirectoryError> {
        let response = self.request(&url, "").await?;
        serde_json::from_str(&response.1).map_err(Into::into)
    }

    pub async fn finalize(
        &self,
        url: impl AsRef<str>,
        csr: Vec<u8>,
    ) -> Result<Order, DirectoryError> {
        let payload = format!("{{\"csr\":\"{}\"}}", URL_SAFE_NO_PAD.encode(csr));
        let response = self.request(&url, &payload).await?;
        serde_json::from_str(&response.1).map_err(Into::into)
    }

    pub async fn certificate(&self, url: impl AsRef<str>) -> Result<String, DirectoryError> {
        Ok(self.request(&url, "").await?.1)
    }

    pub fn http_proof(&self, challenge: &Challenge) -> Result<Vec<u8>, DirectoryError> {
        key_authorization(&self.key_pair, &challenge.token)
            .map(|key| key.into_bytes())
            .map_err(Into::into)
    }

    pub fn dns_proof(&self, challenge: &Challenge) -> Result<String, DirectoryError> {
        key_authorization_sha256_base64(&self.key_pair, &challenge.token).map_err(Into::into)
    }

    pub fn tls_alpn_key(
        &self,
        challenge: &Challenge,
        domain: String,
    ) -> Result<Vec<u8>, DirectoryError> {
        let mut params = rcgen::CertificateParams::new(vec![domain]);
        let key_auth = key_authorization_sha256(&self.key_pair, &challenge.token)?;
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];
        let cert = Certificate::from_params(params)?;

        Ok(Bincode::new(SerializedCert {
            certificate: cert.serialize_der()?,
            private_key: cert.serialize_private_key_der(),
        })
        .serialize())
    }
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct SerializedCert {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl Directory {
    pub async fn discover(url: impl AsRef<str>) -> Result<Self, DirectoryError> {
        Ok(serde_json::from_str(
            &https(url, Method::GET, None).await?.text().await?,
        )?)
    }
    pub async fn nonce(&self) -> Result<String, DirectoryError> {
        get_header(
            &https(&self.new_nonce.as_str(), Method::HEAD, None).await?,
            "replay-nonce",
        )
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone, Copy)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    #[serde(flatten)]
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub error: Option<Problem>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Valid { certificate: String },
    Invalid,
    Processing,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub status: AuthStatus,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
    pub wildcard: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub token: String,
    pub error: Option<Problem>,
}

#[derive(Clone, Debug, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub enum DirectoryError {
    Io(std::io::Error),
    Rcgen(rcgen::Error),
    Jose(JoseError),
    Json(serde_json::Error),
    HttpRequest(reqwest::Error),
    HttpRequestCode { code: StatusCode, reason: String },
    HttpResponseNonStringHeader(ToStrError),
    KeyRejected(KeyRejected),
    Crypto(Unspecified),
    MissingHeader(&'static str),
    NoChallenge(ChallengeType),
}

#[allow(unused_mut)]
async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response, DirectoryError> {
    let url = url.as_ref();
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .http1_only();

    #[cfg(debug_assertions)]
    {
        builder = builder.danger_accept_invalid_certs(
            url.starts_with("https://localhost") || url.starts_with("https://127.0.0.1"),
        );
    }

    let mut request = builder.build()?.request(method, url);

    if let Some(body) = body {
        request = request
            .header(CONTENT_TYPE, "application/jose+json")
            .body(body);
    }

    let response = request.send().await?;
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(DirectoryError::HttpRequestCode {
            code: response.status(),
            reason: response.text().await?,
        })
    }
}

fn get_header(response: &Response, header: &'static str) -> Result<String, DirectoryError> {
    match response.headers().get_all(header).iter().last() {
        Some(value) => Ok(value.to_str()?.to_string()),
        None => Err(DirectoryError::MissingHeader(header)),
    }
}

impl From<std::io::Error> for DirectoryError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rcgen::Error> for DirectoryError {
    fn from(err: rcgen::Error) -> Self {
        Self::Rcgen(err)
    }
}

impl From<JoseError> for DirectoryError {
    fn from(err: JoseError) -> Self {
        Self::Jose(err)
    }
}

impl From<serde_json::Error> for DirectoryError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<reqwest::Error> for DirectoryError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpRequest(err)
    }
}

impl From<KeyRejected> for DirectoryError {
    fn from(err: KeyRejected) -> Self {
        Self::KeyRejected(err)
    }
}

impl From<Unspecified> for DirectoryError {
    fn from(err: Unspecified) -> Self {
        Self::Crypto(err)
    }
}

impl From<ToStrError> for DirectoryError {
    fn from(err: ToStrError) -> Self {
        Self::HttpResponseNonStringHeader(err)
    }
}
