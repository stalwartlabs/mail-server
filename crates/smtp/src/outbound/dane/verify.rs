/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::Tlsa;
use rustls_pki_types::CertificateDer;
use sha1::Digest;
use sha2::{Sha256, Sha512};
use trc::DaneEvent;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::queue::{Error, ErrorDetails, Status};

pub trait TlsaVerify {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<(), Error>>;
}

impl TlsaVerify for Tlsa {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<(), Error>> {
        let certificates = if let Some(certificates) = certificates {
            certificates
        } else {
            trc::event!(
                Dane(DaneEvent::NoCertificatesFound),
                SessionId = session_id,
                Hostname = hostname.to_string(),
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
                    trc::event!(
                        Dane(DaneEvent::CertificateParseError),
                        SessionId = session_id,
                        Hostname = hostname.to_string(),
                        Reason = err.to_string(),
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
                        trc::event!(
                            Dane(DaneEvent::TlsaRecordMatch),
                            SessionId = session_id,
                            Hostname = hostname.to_string(),
                            Type = if is_end_entity {
                                "end-entity"
                            } else {
                                "intermediate"
                            },
                            Details = format!("{:x?}", hash),
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

        // DANE is valid if:
        // - EE matched even if no TA matched
        // - Both EE and TA matched
        // - EE is not present and TA matched
        if (self.has_end_entities && matched_end_entity)
            || ((self.has_end_entities == matched_end_entity)
                && (self.has_intermediates == matched_intermediate))
        {
            trc::event!(
                Dane(DaneEvent::AuthenticationSuccess),
                SessionId = session_id,
                Hostname = hostname.to_string(),
            );

            Ok(())
        } else {
            trc::event!(
                Dane(DaneEvent::AuthenticationFailure),
                SessionId = session_id,
                Hostname = hostname.to_string(),
            );

            Err(Status::PermanentFailure(Error::DaneError(ErrorDetails {
                entity: hostname.to_string(),
                details: "No matching certificates found in TLSA records".to_string(),
            })))
        }
    }
}
