// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use chrono::{DateTime, TimeZone, Utc};
use dns_update::DnsRecord;
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::{Duration, Instant};
use utils::suffixlist::DomainPart;
use x509_parser::parse_x509_certificate;

use crate::listener::acme::directory::Identifier;
use crate::listener::acme::ChallengeSettings;
use crate::Core;

use super::directory::{Account, AuthStatus, Directory, OrderStatus};
use super::AcmeProvider;

impl Core {
    pub(crate) async fn process_cert(
        &self,
        provider: &AcmeProvider,
        pem: Vec<u8>,
        cached: bool,
    ) -> trc::Result<Duration> {
        let (cert, validity) = parse_cert(&pem)?;

        self.set_cert(provider, Arc::new(cert));

        let renew_at = (validity[1] - provider.renew_before - Utc::now())
            .max(chrono::Duration::zero())
            .to_std()
            .unwrap_or_default();
        let renewal_date = validity[1] - provider.renew_before;

        tracing::info!(
            context = "acme",
            event = "process-cert",
            valid_not_before = %validity[0],
            valid_not_after = %validity[1],
            renewal_date = ?renewal_date,
            domains = ?provider.domains,
            "Loaded certificate for domains {:?}", provider.domains);

        if !cached {
            self.store_cert(provider, &pem).await?;
        }

        Ok(renew_at)
    }

    pub async fn renew(&self, provider: &AcmeProvider) -> trc::Result<Duration> {
        let mut backoff = 0;
        loop {
            match self.order(provider).await {
                Ok(pem) => return self.process_cert(provider, pem, false).await,
                Err(err) if backoff < 16 => {
                    tracing::debug!(
                        context = "acme",
                        event = "renew-backoff",
                        domains = ?provider.domains,
                        attempt = backoff,
                        reason = ?err,
                        "Failed to renew certificate, backing off for {} seconds",
                        1 << backoff);
                    backoff = (backoff + 1).min(16);
                    tokio::time::sleep(Duration::from_secs(1 << backoff)).await;
                }
                Err(err) => return Err(err.details("Failed to renew certificate")),
            }
        }
    }

    async fn order(&self, provider: &AcmeProvider) -> trc::Result<Vec<u8>> {
        let directory = Directory::discover(&provider.directory_url).await?;
        let account = Account::create_with_keypair(
            directory,
            &provider.contact,
            provider.account_key.load().as_slice(),
        )
        .await?;

        let mut params = CertificateParams::new(provider.domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params)
            .map_err(|err| trc::Cause::Acme.caused_by(trc::location!()).reason(err))?;

        let (order_url, mut order) = account.new_order(provider.domains.clone()).await?;
        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| self.authorize(provider, &account, url));
                    try_join_all(auth_futures).await?;
                    tracing::info!(
                        context = "acme",
                        event = "auth-complete",
                        domains = ?provider.domains.as_slice(),
                        "Completed all authorizations"
                    );
                    order = account.order(&order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        tracing::info!(
                            context = "acme",
                            event = "processing",
                            domains = ?provider.domains.as_slice(),
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
                        return Err(trc::Cause::Acme
                            .caused_by(trc::location!())
                            .details("Order processing timed out"));
                    }
                }
                OrderStatus::Ready => {
                    tracing::info!(
                        context = "acme",
                        event = "csr-send",
                        domains = ?provider.domains.as_slice(),
                        "Sending CSR"
                    );

                    let csr = cert
                        .serialize_request_der()
                        .map_err(|err| trc::Cause::Acme.caused_by(trc::location!()).reason(err))?;
                    order = account.finalize(order.finalize, csr).await?
                }
                OrderStatus::Valid { certificate } => {
                    tracing::info!(
                        context = "acme",
                        event = "download",
                        domains = ?provider.domains.as_slice(),
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
                        domains = ?provider.domains.as_slice(),
                        "Invalid order"
                    );

                    return Err(trc::Cause::Acme.into_err().details("Invalid ACME order"));
                }
            }
        }
    }

    async fn authorize(
        &self,
        provider: &AcmeProvider,
        account: &Account,
        url: &String,
    ) -> trc::Result<()> {
        let auth = account.auth(url).await?;
        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;
                let challenge_type = provider.challenge.challenge_type();
                tracing::info!(
                    context = "acme",
                    event = "challenge",
                    domain = domain,
                    challenge = ?challenge_type,
                    "Requesting challenge for domain {domain}"
                );
                let challenge = auth
                    .challenges
                    .iter()
                    .find(|c| c.typ == challenge_type)
                    .ok_or(
                        trc::Cause::Acme
                            .into_err()
                            .details("Missing Parameter")
                            .ctx(trc::Key::Id, challenge_type.as_str()),
                    )?;

                match &provider.challenge {
                    ChallengeSettings::TlsAlpn01 => {
                        self.storage
                            .lookup
                            .key_set(
                                format!("acme:{domain}").into_bytes(),
                                account.tls_alpn_key(challenge, domain.clone())?,
                                3600.into(),
                            )
                            .await?;
                    }
                    ChallengeSettings::Http01 => {
                        self.storage
                            .lookup
                            .key_set(
                                format!("acme:{}", challenge.token).into_bytes(),
                                account.http_proof(challenge)?,
                                3600.into(),
                            )
                            .await?;
                    }
                    ChallengeSettings::Dns01 {
                        updater,
                        origin,
                        polling_interval,
                        propagation_timeout,
                        ttl,
                    } => {
                        let dns_proof = account.dns_proof(challenge)?;
                        let domain = domain.strip_prefix("*.").unwrap_or(&domain);
                        let name = format!("_acme-challenge.{}", domain);
                        let origin = origin
                            .clone()
                            .or_else(|| {
                                self.smtp.resolvers.psl.domain_part(domain, DomainPart::Sld)
                            })
                            .unwrap_or_else(|| domain.to_string());

                        // First try deleting the record
                        if let Err(err) = updater.delete(&name, &origin).await {
                            // Errors are expected if the record does not exist
                            tracing::trace!(
                                context = "acme",
                                event = "dns-delete",
                                name = name,
                                origin = origin,
                                error = ?err,
                            );
                        }

                        // Create the record
                        if let Err(err) = updater
                            .create(
                                &name,
                                DnsRecord::TXT {
                                    content: dns_proof.clone(),
                                },
                                *ttl,
                                &origin,
                            )
                            .await
                        {
                            tracing::warn!(
                                context = "acme",
                                event = "dns-create",
                                name = name,
                                origin = origin,
                                error = ?err,
                                "Failed to create DNS record.",
                            );
                            return Err(trc::Cause::Dns.caused_by(trc::location!()).reason(err));
                        }

                        tracing::info!(
                            context = "acme",
                            event = "dns-create",
                            name = name,
                            origin = origin,
                            "Successfully created DNS record.",
                        );

                        // Wait for changes to propagate
                        let wait_until = Instant::now() + *propagation_timeout;
                        let mut did_propagate = false;
                        while Instant::now() < wait_until {
                            match self.smtp.resolvers.dns.txt_raw_lookup(&name).await {
                                Ok(result) => {
                                    let result = std::str::from_utf8(&result).unwrap_or_default();
                                    if result.contains(&dns_proof) {
                                        did_propagate = true;
                                        break;
                                    } else {
                                        tracing::debug!(
                                            context = "acme",
                                            event = "dns-lookup",
                                            name = name,
                                            origin = origin,
                                            contents = ?result,
                                            expected_proof = ?dns_proof,
                                            "DNS record has not propagated yet.",
                                        );
                                    }
                                }
                                Err(err) => {
                                    tracing::trace!(
                                        context = "acme",
                                        event = "dns-lookup",
                                        name = name,
                                        origin = origin,
                                        error = ?err,
                                        "Failed to lookup DNS record.",
                                    );
                                }
                            }

                            tokio::time::sleep(*polling_interval).await;
                        }

                        if did_propagate {
                            tracing::info!(
                                context = "acme",
                                event = "dns-lookup",
                                name = name,
                                origin = origin,
                                "DNS changes have been propagated.",
                            );
                        } else {
                            tracing::warn!(
                                context = "acme",
                                event = "dns-lookup",
                                name = name,
                                origin = origin,
                                "DNS changes have not been propagated within the timeout.",
                            );
                        }
                    }
                }

                account.challenge(&challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => {
                return Err(trc::Cause::Acme
                    .into_err()
                    .details("Authentication error")
                    .ctx(trc::Key::Status, auth.status.as_str()))
            }
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
                AuthStatus::Valid => {
                    tracing::debug!(
                        context = "acme",
                        event = "auth-valid",
                        domain = domain,
                        "Authorization for domain {domain} is valid",
                    );

                    return Ok(());
                }
                _ => {
                    return Err(trc::Cause::Acme
                        .into_err()
                        .details("Authentication error")
                        .ctx(trc::Key::Status, auth.status.as_str()))
                }
            }
        }
        Err(trc::Cause::Acme
            .into_err()
            .details("Too many authentication attempts")
            .ctx(trc::Key::Id, domain))
    }
}

fn parse_cert(pem: &[u8]) -> trc::Result<(CertifiedKey, [DateTime<Utc>; 2])> {
    let mut pems = pem::parse_many(pem)
        .map_err(|err| trc::Cause::Acme.reason(err).caused_by(trc::location!()))?;
    if pems.len() < 2 {
        return Err(trc::Cause::Acme
            .caused_by(trc::location!())
            .ctx(trc::Key::Size, pems.len())
            .details("Too few PEMs"));
    }
    let pk = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pems.remove(0).contents(),
    ))) {
        Ok(pk) => pk,
        Err(err) => return Err(trc::Cause::Acme.reason(err).caused_by(trc::location!())),
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
        Err(err) => return Err(trc::Cause::Acme.reason(err).caused_by(trc::location!())),
    };
    let cert = CertifiedKey::new(cert_chain, pk);
    Ok((cert, validity))
}
