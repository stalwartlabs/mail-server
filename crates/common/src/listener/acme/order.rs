// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use chrono::{DateTime, TimeZone, Utc};
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::parse_x509_certificate;

use crate::listener::acme::directory::Identifier;

use super::directory::{Account, Auth, AuthStatus, Directory, DirectoryError, Order, OrderStatus};
use super::jose::JoseError;
use super::{AcmeError, AcmeManager};

#[derive(Debug)]
pub enum OrderError {
    Acme(DirectoryError),
    Rcgen(rcgen::Error),
    BadOrder(Order),
    BadAuth(Auth),
    TooManyAttemptsAuth(String),
    ProcessingTimeout(Order),
}

#[derive(Debug)]
pub enum CertParseError {
    X509(x509_parser::nom::Err<x509_parser::error::X509Error>),
    Pem(pem::PemError),
    TooFewPem(usize),
    InvalidPrivateKey,
}

impl AcmeManager {
    pub(crate) async fn process_cert(
        &self,
        pem: Vec<u8>,
        cached: bool,
    ) -> Result<Duration, AcmeError> {
        let (cert, validity) = match (parse_cert(&pem), cached) {
            (Ok(r), _) => r,
            (Err(err), cached) => {
                return match cached {
                    true => Err(AcmeError::CachedCertParse(err)),
                    false => Err(AcmeError::NewCertParse(err)),
                }
            }
        };

        self.set_cert(Arc::new(cert));

        let renew_at = (validity[1] - self.renew_before - Utc::now())
            .max(chrono::Duration::zero())
            .to_std()
            .unwrap_or_default();
        let renewal_date = validity[1] - self.renew_before;

        tracing::info!(
            context = "acme",
            event = "process-cert",
            valid_not_before = %validity[0],
            valid_not_after = %validity[1],
            renewal_date = ?renewal_date,
            domains = ?self.domains,
            "Loaded certificate for domains {:?}", self.domains);

        if !cached {
            self.store_cert(&pem).await?;
        }

        Ok(renew_at)
    }

    pub async fn renew(&self) -> Result<Duration, AcmeError> {
        let mut backoff = 0;
        self.order_in_progress.store(true, Ordering::Relaxed);
        loop {
            match self.order().await {
                Ok(pem) => return self.process_cert(pem, false).await,
                Err(err) if backoff < 16 => {
                    tracing::debug!(
                        context = "acme",
                        event = "renew-backoff",
                        domains = ?self.domains,
                        attempt = backoff,
                        reason = ?err,
                        "Failed to renew certificate, backing off for {} seconds",
                        1 << backoff);
                    backoff = (backoff + 1).min(16);
                    tokio::time::sleep(Duration::from_secs(1 << backoff)).await;
                }
                Err(err) => return Err(AcmeError::Order(err)),
            }
        }
    }

    async fn order(&self) -> Result<Vec<u8>, OrderError> {
        let directory = Directory::discover(&self.directory_url).await?;
        let account = Account::create_with_keypair(
            directory,
            &self.contact,
            self.account_key.load().as_slice(),
        )
        .await?;

        let mut params = CertificateParams::new(self.domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params)?;

        let (order_url, mut order) = account.new_order(self.domains.clone()).await?;
        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| self.authorize(&account, url));
                    try_join_all(auth_futures).await?;
                    tracing::info!(
                        context = "acme",
                        event = "auth-complete",
                        domains = ?self.domains.as_slice(),
                        "Completed all authorizations"
                    );
                    order = account.order(&order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        tracing::info!(
                            context = "acme",
                            event = "processing",
                            domains = ?self.domains.as_slice(),
                            attempt = i,
                            "Processing order"
                        );
                        tokio::time::sleep(Duration::from_secs(1u64 << i)).await;
                        order = account.order(&order_url).await?;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(OrderError::ProcessingTimeout(order));
                    }
                }
                OrderStatus::Ready => {
                    tracing::info!(
                        context = "acme",
                        event = "csr-send",
                        domains = ?self.domains.as_slice(),
                        "Sending CSR"
                    );

                    let csr = cert.serialize_request_der()?;
                    order = account.finalize(order.finalize, csr).await?
                }
                OrderStatus::Valid { certificate } => {
                    tracing::info!(
                        context = "acme",
                        event = "download",
                        domains = ?self.domains.as_slice(),
                        "Downloading certificate"
                    );

                    let pem = [
                        &cert.serialize_private_key_pem(),
                        "\n",
                        &account.certificate(certificate).await?,
                    ]
                    .concat();
                    return Ok(pem.into_bytes());
                }
                OrderStatus::Invalid => {
                    tracing::warn!(
                        context = "acme",
                        event = "error",
                        reason = "invalid-order",
                        domains = ?self.domains.as_slice(),
                        "Invalid order"
                    );

                    return Err(OrderError::BadOrder(order));
                }
            }
        }
    }

    async fn authorize(&self, account: &Account, url: &String) -> Result<(), OrderError> {
        let auth = account.auth(url).await?;
        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;
                tracing::info!(
                    context = "acme",
                    event = "challenge",
                    domain = domain,
                    "Requesting challenge for domain {domain}"
                );
                let (challenge, auth_key) =
                    account.tls_alpn_01(&auth.challenges, domain.clone())?;
                self.set_auth_key(domain.clone(), Arc::new(auth_key));
                account.challenge(&challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            tokio::time::sleep(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(url).await?;
            match auth.status {
                AuthStatus::Pending => {
                    tracing::info!(
                        context = "acme",
                        event = "auth-pending",
                        domain = domain,
                        attempt = i,
                        "Authorization for domain {domain} is still pending",
                    );
                    account.challenge(&challenge_url).await?
                }
                AuthStatus::Valid => return Ok(()),
                _ => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(domain))
    }
}

fn parse_cert(pem: &[u8]) -> Result<(CertifiedKey, [DateTime<Utc>; 2]), CertParseError> {
    let mut pems = pem::parse_many(pem)?;
    if pems.len() < 2 {
        return Err(CertParseError::TooFewPem(pems.len()));
    }
    let pk = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pems.remove(0).contents(),
    ))) {
        Ok(pk) => pk,
        Err(_) => return Err(CertParseError::InvalidPrivateKey),
    };
    let cert_chain: Vec<CertificateDer> = pems
        .into_iter()
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();
    let validity = match parse_x509_certificate(&cert_chain[0]) {
        Ok((_, cert)) => {
            let validity = cert.validity();
            [validity.not_before, validity.not_after].map(|t| {
                Utc.timestamp_opt(t.timestamp(), 0)
                    .earliest()
                    .unwrap_or_default()
            })
        }
        Err(err) => return Err(CertParseError::X509(err)),
    };
    let cert = CertifiedKey::new(cert_chain, pk);
    Ok((cert, validity))
}

impl From<DirectoryError> for OrderError {
    fn from(err: DirectoryError) -> Self {
        Self::Acme(err)
    }
}

impl From<rcgen::Error> for OrderError {
    fn from(err: rcgen::Error) -> Self {
        Self::Rcgen(err)
    }
}

impl From<x509_parser::nom::Err<x509_parser::error::X509Error>> for CertParseError {
    fn from(err: x509_parser::nom::Err<x509_parser::error::X509Error>) -> Self {
        Self::X509(err)
    }
}

impl From<pem::PemError> for CertParseError {
    fn from(err: pem::PemError) -> Self {
        Self::Pem(err)
    }
}

impl From<JoseError> for OrderError {
    fn from(err: JoseError) -> Self {
        Self::Acme(DirectoryError::Jose(err))
    }
}

impl From<JoseError> for AcmeError {
    fn from(err: JoseError) -> Self {
        Self::Order(OrderError::from(err))
    }
}
