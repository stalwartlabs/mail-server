/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

pub mod codec;
pub mod config;
pub mod glob;
pub mod lru_cache;
pub mod map;
pub mod snowflake;
pub mod suffixlist;
pub mod url_params;

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    ClientConfig, RootCertStore, SignatureScheme,
};
use rustls_pki_types::TrustAnchor;

pub const BLOB_HASH_LEN: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BlobHash([u8; BLOB_HASH_LEN]);

impl BlobHash {
    pub fn new_max() -> Self {
        BlobHash([u8::MAX; BLOB_HASH_LEN])
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

impl From<&[u8]> for BlobHash {
    fn from(value: &[u8]) -> Self {
        BlobHash(blake3::hash(value).into())
    }
}

impl From<Vec<u8>> for BlobHash {
    fn from(value: Vec<u8>) -> Self {
        value.as_slice().into()
    }
}

impl From<&Vec<u8>> for BlobHash {
    fn from(value: &Vec<u8>) -> Self {
        value.as_slice().into()
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
                    Details = message.to_string()
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
                    Details = message.to_string(),
                    Reason = err.to_string()
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
        Details = message.to_string(),
    );
    eprintln!("{message}");
    std::process::exit(1);
}

pub async fn wait_for_shutdown(message: &str) {
    #[cfg(not(target_env = "msvc"))]
    let signal = {
        use tokio::signal::unix::{signal, SignalKind};

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
                    Server(trc::ServerEvent::Error),
                    Details = "Unable to listen for shutdown signal",
                    Reason = err.to_string(),
                );
                "Error"
            }
        }
    };

    trc::event!(
        Server(trc::ServerEvent::Shutdown),
        Details = message.to_string(),
        CausedBy = signal
    );
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
