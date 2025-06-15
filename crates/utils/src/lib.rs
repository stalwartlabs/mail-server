/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, sync::Arc};

pub mod bimap;
pub mod cache;
pub mod codec;
pub mod config;
pub mod glob;
pub mod json;
pub mod map;
pub mod snowflake;
pub mod template;
pub mod topological;
pub mod url_params;

use compact_str::ToCompactString;
use futures::StreamExt;
use reqwest::Response;
use rustls::{
    ClientConfig, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls_pki_types::TrustAnchor;

pub use downcast_rs;
pub use erased_serde;

pub const BLOB_HASH_LEN: usize = 32;

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[rkyv(derive(Debug))]
#[repr(transparent)]
pub struct BlobHash(pub [u8; BLOB_HASH_LEN]);

impl BlobHash {
    pub fn new_max() -> Self {
        BlobHash([u8::MAX; BLOB_HASH_LEN])
    }

    pub fn generate(value: impl AsRef<[u8]>) -> Self {
        BlobHash(blake3::hash(value.as_ref()).into())
    }

    pub fn try_from_hash_slice(value: &[u8]) -> Result<BlobHash, std::array::TryFromSliceError> {
        value.try_into().map(BlobHash)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(BLOB_HASH_LEN * 2);
        for byte in self.0.iter() {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }
}

impl From<&ArchivedBlobHash> for BlobHash {
    fn from(value: &ArchivedBlobHash) -> Self {
        BlobHash(value.0)
    }
}

impl AsRef<BlobHash> for BlobHash {
    fn as_ref(&self) -> &BlobHash {
        self
    }
}

impl From<BlobHash> for Vec<u8> {
    fn from(value: BlobHash) -> Self {
        value.0.to_vec()
    }
}

impl AsRef<[u8]> for BlobHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for BlobHash {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

pub trait HttpLimitResponse: Sync + Send {
    fn bytes_with_limit(
        self,
        limit: usize,
    ) -> impl std::future::Future<Output = reqwest::Result<Option<Vec<u8>>>> + Send;
}

impl HttpLimitResponse for Response {
    async fn bytes_with_limit(self, limit: usize) -> reqwest::Result<Option<Vec<u8>>> {
        if self
            .content_length()
            .is_some_and(|len| len as usize > limit)
        {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(std::cmp::min(limit, 1024));
        let mut stream = self.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Some(bytes))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Semver(u64);

impl Semver {
    pub fn current() -> Self {
        env!("CARGO_PKG_VERSION").try_into().unwrap()
    }

    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        let mut version: u64 = 0;
        version |= (major as u64) << 32;
        version |= (minor as u64) << 16;
        version |= patch as u64;
        Semver(version)
    }

    pub fn unpack(&self) -> (u16, u16, u16) {
        let version = self.0;
        let major = ((version >> 32) & 0xFFFF) as u16;
        let minor = ((version >> 16) & 0xFFFF) as u16;
        let patch = (version & 0xFFFF) as u16;
        (major, minor, patch)
    }

    pub fn major(&self) -> u16 {
        (self.0 >> 32) as u16
    }

    pub fn minor(&self) -> u16 {
        (self.0 >> 16) as u16
    }

    pub fn patch(&self) -> u16 {
        self.0 as u16
    }

    pub fn is_valid(&self) -> bool {
        self.0 > 0
    }
}

impl AsRef<u64> for Semver {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl From<u64> for Semver {
    fn from(value: u64) -> Self {
        Semver(value)
    }
}

impl TryFrom<&str> for Semver {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(3, '.');
        let major = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let minor = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        let patch = parts.next().ok_or(())?.parse().map_err(|_| ())?;
        Ok(Semver::new(major, minor, patch))
    }
}

impl Display for Semver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.unpack();
        write!(f, "{major}.{minor}.{patch}")
    }
}

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string()
                );
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapFailure<T> for Result<T, E> {
    fn failed(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::StartupError),
                    Details = message.to_compact_string(),
                    Reason = err.to_compact_string()
                );

                #[cfg(feature = "test_mode")]
                panic!("{message}: {err}");

                #[cfg(not(feature = "test_mode"))]
                {
                    eprintln!("{message}: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    trc::event!(
        Server(trc::ServerEvent::StartupError),
        Details = message.to_compact_string(),
    );
    eprintln!("{message}");
    std::process::exit(1);
}

pub async fn wait_for_shutdown() {
    #[cfg(not(target_env = "msvc"))]
    let signal = {
        use tokio::signal::unix::{SignalKind, signal};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => "SIGTERM",
            _ = h_int.recv() => "SIGINT",
        }
    };

    #[cfg(target_env = "msvc")]
    let signal = {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(err) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Unable to listen for shutdown signal",
                    Reason = err.to_string(),
                );
                "Error"
            }
        }
    };

    trc::event!(Server(trc::ServerEvent::Shutdown), CausedBy = signal);
}

pub fn rustls_client_config(allow_invalid_certs: bool) -> ClientConfig {
    let config = ClientConfig::builder();

    if !allow_invalid_certs {
        let mut root_cert_store = RootCertStore::empty();

        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| TrustAnchor {
            subject: ta.subject.clone(),
            subject_public_key_info: ta.subject_public_key_info.clone(),
            name_constraints: ta.name_constraints.clone(),
        }));

        config
            .with_root_certificates(root_cert_store)
            .with_no_client_auth()
    } else {
        config
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
            .with_no_client_auth()
    }
}

#[derive(Debug)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// Basic email sanitizer
pub fn sanitize_email(email: &str) -> Option<String> {
    let mut result = String::with_capacity(email.len());
    let mut found_local = false;
    let mut found_domain = false;
    let mut last_ch = char::from(0);

    for ch in email.chars() {
        if !ch.is_whitespace() {
            if ch == '@' {
                if !result.is_empty() && !found_local {
                    found_local = true;
                } else {
                    return None;
                }
            } else if ch == '.' {
                if !(last_ch.is_alphanumeric() || last_ch == '-' || last_ch == '_') {
                    return None;
                } else if found_local {
                    found_domain = true;
                }
            }
            last_ch = ch;
            for ch in ch.to_lowercase() {
                result.push(ch);
            }
        }
    }

    if found_domain
        && last_ch != '.'
        && psl::domain(result.as_bytes()).is_some_and(|d| d.suffix().typ().is_some())
    {
        Some(result)
    } else {
        None
    }
}
