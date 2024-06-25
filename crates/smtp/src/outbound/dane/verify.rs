/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::Tlsa;
use rustls_pki_types::CertificateDer;
use sha1::Digest;
use sha2::{Sha256, Sha512};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::queue::{Error, ErrorDetails, Status};

pub trait TlsaVerify {
    fn verify(
        &self,
        span: &tracing::Span,
        hostname: &str,
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<(), Error>>;
}

impl TlsaVerify for Tlsa {
    fn verify(
        &self,
        span: &tracing::Span,
        hostname: &str,
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<(), Error>> {
        let certificates = if let Some(certificates) = certificates {
            certificates
        } else {
            tracing::info!(
                parent: span,
                context = "dane",
                event = "no-server-certs-found",
                mx = hostname,
                "No certificates were provided."
            );
            return Err(Status::TemporaryFailure(Error::DaneError(ErrorDetails {
                entity: hostname.to_string(),
                details: "No certificates were provided by host".to_string(),
            })));
        };

        let mut matched_end_entity = false;
        let mut matched_intermediate = false;
        'outer: for (pos, der_certificate) in certificates.iter().enumerate() {
            // Parse certificate
            let certificate = match X509Certificate::from_der(der_certificate.as_ref()) {
                Ok((_, certificate)) => certificate,
                Err(err) => {
                    tracing::debug!(
                        parent: span,
                        context = "dane",
                        event = "cert-parse-error",
                        "Failed to parse X.509 certificate for host {}: {}",
                        hostname,
                        err
                    );
                    return Err(Status::TemporaryFailure(Error::DaneError(ErrorDetails {
                        entity: hostname.to_string(),
                        details: "Failed to parse X.509 certificate".to_string(),
                    })));
                }
            };

            // Match against TLSA records
            let is_end_entity = pos == 0;
            let mut sha256 = [None, None];
            let mut sha512 = [None, None];
            for record in self.entries.iter() {
                if record.is_end_entity == is_end_entity {
                    let hash: &[u8] = if record.is_sha256 {
                        &sha256[usize::from(record.is_spki)].get_or_insert_with(|| {
                            let mut hasher = Sha256::new();
                            hasher.update(if record.is_spki {
                                certificate.public_key().raw
                            } else {
                                der_certificate.as_ref()
                            });
                            hasher.finalize()
                        })[..]
                    } else {
                        &sha512[usize::from(record.is_spki)].get_or_insert_with(|| {
                            let mut hasher = Sha512::new();
                            hasher.update(if record.is_spki {
                                certificate.public_key().raw
                            } else {
                                der_certificate.as_ref()
                            });
                            hasher.finalize()
                        })[..]
                    };

                    if hash == record.data {
                        tracing::debug!(
                            parent: span,
                            context = "dane",
                            event = "info",
                            mx = hostname,
                            certificate = if is_end_entity {
                                "end-entity"
                            } else {
                                "intermediate"
                            },
                            "Matched TLSA record with hash {:x?}.",
                            hash
                        );

                        if is_end_entity {
                            matched_end_entity = true;
                            if !self.has_intermediates {
                                break 'outer;
                            }
                        } else {
                            matched_intermediate = true;
                            break 'outer;
                        }
                    }
                }
            }
        }

        if (self.has_end_entities == matched_end_entity)
            && (self.has_intermediates == matched_intermediate)
        {
            tracing::info!(
                parent: span,
                context = "dane",
                event = "authenticated",
                mx = hostname,
                "DANE authentication successful.",
            );
            Ok(())
        } else {
            tracing::warn!(
                parent: span,
                context = "dane",
                event = "auth-failure",
                mx = hostname,
                "No matching certificates found in TLSA records.",
            );
            Err(Status::PermanentFailure(Error::DaneError(ErrorDetails {
                entity: hostname.to_string(),
                details: "No matching certificates found in TLSA records".to_string(),
            })))
        }
    }
}
