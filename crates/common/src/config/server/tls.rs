/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::{
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use rcgen::generate_simple_self_signed;
use rustls::{
    crypto::ring::sign::any_supported_type,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    SupportedProtocolVersion,
};
use rustls_pemfile::{certs, read_one, Item};
use rustls_pki_types::PrivateKeyDer;
use utils::config::Config;
use x509_parser::{
    certificate::X509Certificate,
    der_parser::asn1_rs::FromDer,
    extensions::{GeneralName, ParsedExtension},
};

use crate::listener::{
    acme::{directory::LETS_ENCRYPT_PRODUCTION_DIRECTORY, AcmeProvider},
    tls::TlsManager,
};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

impl TlsManager {
    pub fn parse(config: &mut Config) -> Self {
        let mut certificates = AHashMap::new();
        let mut acme_providers = AHashMap::new();
        let mut subject_names = AHashSet::new();

        // Parse certificates
        parse_certificates(config, &mut certificates, &mut subject_names);

        // Parse ACME providers
        for acme_id in config
            .sub_keys("acme", ".directory")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            let directory = config
                .value(("acme", acme_id.as_str(), "directory"))
                .unwrap_or(LETS_ENCRYPT_PRODUCTION_DIRECTORY)
                .trim()
                .to_string();
            let contact = config
                .values(("acme", acme_id.as_str(), "contact"))
                .filter_map(|(_, v)| {
                    let v = v.trim().to_string();
                    if !v.is_empty() {
                        Some(v)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            let renew_before: Duration = config
                .property_or_default(("acme", acme_id.as_str(), "renew-before"), "30d")
                .unwrap_or_else(|| Duration::from_secs(30 * 24 * 60 * 60));

            if directory.is_empty() {
                config.new_parse_error(format!("acme.{acme_id}.directory"), "Missing property");
                continue;
            }

            if contact.is_empty() {
                config.new_parse_error(format!("acme.{acme_id}.contact"), "Missing property");
                continue;
            }

            // Domains covered by this ACME manager
            let domains = config
                .values(("acme", acme_id.as_str(), "domains"))
                .map(|(_, v)| v.to_string())
                .collect::<Vec<_>>();

            // Add domains for self-signed certificate
            subject_names.extend(domains.iter().cloned());

            if !domains.is_empty() {
                match AcmeProvider::new(
                    acme_id.to_string(),
                    directory,
                    domains,
                    contact,
                    renew_before,
                ) {
                    Ok(acme_provider) => {
                        acme_providers.insert(acme_id.to_string(), acme_provider);
                    }
                    Err(err) => {
                        config.new_build_error(format!("acme.{acme_id}"), err);
                    }
                }
            }
        }

        if subject_names.is_empty() {
            subject_names.insert("localhost".to_string());
        }

        TlsManager {
            certificates: ArcSwap::from_pointee(certificates),
            acme_providers,
            acme_auth_keys: Default::default(),
            acme_in_progress: false.into(),
            self_signed_cert: build_self_signed_cert(subject_names.into_iter().collect::<Vec<_>>())
                .or_else(|err| {
                    config.new_build_error("certificate.self-signed", err);
                    build_self_signed_cert(vec!["localhost".to_string()])
                })
                .ok()
                .map(Arc::new),
        }
    }
}

pub(crate) fn parse_certificates(
    config: &mut Config,
    certificates: &mut AHashMap<String, Arc<CertifiedKey>>,
    subject_names: &mut AHashSet<String>,
) {
    // Parse certificates
    for cert_id in config
        .sub_keys("certificate", ".cert")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        let cert_id = cert_id.as_str();
        let key_cert = ("certificate", cert_id, "cert");
        let key_pk = ("certificate", cert_id, "private-key");

        let cert = config
            .value_require(key_cert)
            .map(|s| s.as_bytes().to_vec());
        let pk = config.value_require(key_pk).map(|s| s.as_bytes().to_vec());

        if let (Some(cert), Some(pk)) = (cert, pk) {
            match build_certified_key(cert, pk) {
                Ok(cert) => {
                    match cert
                        .end_entity_cert()
                        .map_err(|err| format!("Failed to obtain end entity cert: {err}"))
                        .and_then(|cert| {
                            X509Certificate::from_der(cert.as_ref())
                                .map_err(|err| format!("Failed to parse end entity cert: {err}"))
                        }) {
                        Ok((_, parsed)) => {
                            // Add CNs and SANs to the list of names
                            let mut names = AHashSet::new();
                            for name in parsed.subject().iter_common_name() {
                                if let Ok(name) = name.as_str() {
                                    names.insert(name.to_string());
                                }
                            }
                            for ext in parsed.extensions() {
                                if let ParsedExtension::SubjectAlternativeName(san) =
                                    ext.parsed_extension()
                                {
                                    for name in &san.general_names {
                                        let name = match name {
                                            GeneralName::DNSName(name) => name.to_string(),
                                            GeneralName::IPAddress(ip) => match ip.len() {
                                                4 => Ipv4Addr::from(
                                                    <[u8; 4]>::try_from(*ip).unwrap(),
                                                )
                                                .to_string(),
                                                16 => Ipv6Addr::from(
                                                    <[u8; 16]>::try_from(*ip).unwrap(),
                                                )
                                                .to_string(),
                                                _ => continue,
                                            },
                                            _ => {
                                                continue;
                                            }
                                        };
                                        names.insert(name);
                                    }
                                }
                            }

                            // Add custom SNIs
                            names.extend(
                                config
                                    .values(("certificate", cert_id, "subjects"))
                                    .map(|(_, v)| v.trim().to_string()),
                            );

                            // Add domain names
                            subject_names.extend(names.iter().cloned());

                            // Add certificates
                            let cert = Arc::new(cert);
                            for name in names {
                                certificates.insert(
                                    name.strip_prefix("*.")
                                        .map(|name| name.to_string())
                                        .unwrap_or(name),
                                    cert.clone(),
                                );
                            }

                            // Add default certificate
                            if config
                                .property::<bool>(("certificate", cert_id, "default"))
                                .unwrap_or_default()
                            {
                                certificates.insert("*".to_string(), cert.clone());
                            }
                        }
                        Err(err) => config.new_build_error(format!("certificate.{cert_id}"), err),
                    }
                }
                Err(err) => config.new_build_error(format!("certificate.{cert_id}"), err),
            }
        }
    }
}

pub(crate) fn build_certified_key(
    cert: Vec<u8>,
    pk: Vec<u8>,
) -> utils::config::Result<CertifiedKey> {
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates: {err}"))?;
    if cert.is_empty() {
        return Err("No certificates found.".to_string());
    }
    let pk = match read_one(&mut Cursor::new(pk))
        .map_err(|err| format!("Failed to read private keys.: {err}",))?
        .into_iter()
        .next()
    {
        Some(Item::Pkcs8Key(key)) => PrivateKeyDer::Pkcs8(key),
        Some(Item::Pkcs1Key(key)) => PrivateKeyDer::Pkcs1(key),
        Some(Item::Sec1Key(key)) => PrivateKeyDer::Sec1(key),
        Some(_) => return Err("Unsupported private keys found.".to_string()),
        None => return Err("No private keys found.".to_string()),
    };

    Ok(CertifiedKey {
        cert,
        key: any_supported_type(&pk)
            .map_err(|err| format!("Failed to sign certificate: {err}",))?,
        ocsp: None,
    })
}

pub(crate) fn build_self_signed_cert(
    domains: impl Into<Vec<String>>,
) -> utils::config::Result<CertifiedKey> {
    let cert = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
    )
}
