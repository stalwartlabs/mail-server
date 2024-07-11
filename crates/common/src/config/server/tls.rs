/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use base64::{engine::general_purpose::STANDARD, Engine};
use dns_update::{providers::rfc2136::DnsAddress, DnsUpdater, TsigAlgorithm};
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
    acme::{directory::LETS_ENCRYPT_PRODUCTION_DIRECTORY, AcmeProvider, ChallengeSettings},
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
        'outer: for acme_id in config
            .sub_keys("acme", ".directory")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            let acme_id = acme_id.as_str();
            let directory = config
                .value(("acme", acme_id, "directory"))
                .unwrap_or(LETS_ENCRYPT_PRODUCTION_DIRECTORY)
                .trim()
                .to_string();
            let contact = config
                .values(("acme", acme_id, "contact"))
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
                .property_or_default(("acme", acme_id, "renew-before"), "30d")
                .unwrap_or_else(|| Duration::from_secs(30 * 24 * 60 * 60));

            if directory.is_empty() {
                config.new_parse_error(format!("acme.{acme_id}.directory"), "Missing property");
                continue;
            }

            if contact.is_empty() {
                config.new_parse_error(format!("acme.{acme_id}.contact"), "Missing property");
                continue;
            }

            // Parse challenge type
            let challenge = match config
                .value(("acme", acme_id, "challenge"))
                .unwrap_or("tls-alpn-01")
            {
                "tls-alpn-01" => ChallengeSettings::TlsAlpn01,
                "http-01" => ChallengeSettings::Http01,
                "dns-01" => match build_dns_updater(config, acme_id) {
                    Some(updater) => ChallengeSettings::Dns01 {
                        updater,
                        origin: config
                            .value(("acme", acme_id, "origin"))
                            .map(|s| s.to_string()),
                        polling_interval: config
                            .property_or_default(("acme", acme_id, "polling-interval"), "15s")
                            .unwrap_or_else(|| Duration::from_secs(15)),
                        propagation_timeout: config
                            .property_or_default(("acme", acme_id, "propagation-timeout"), "1m")
                            .unwrap_or_else(|| Duration::from_secs(60)),
                        ttl: config
                            .property_or_default(("acme", acme_id, "ttl"), "5m")
                            .unwrap_or_else(|| Duration::from_secs(5 * 60))
                            .as_secs() as u32,
                    },
                    None => {
                        continue;
                    }
                },
                _ => {
                    config
                        .new_parse_error(("acme", acme_id, "challenge"), "Invalid challenge type");
                    continue;
                }
            };

            // Domains covered by this ACME manager
            let domains = config
                .values(("acme", acme_id, "domains"))
                .map(|(_, s)| s.trim().to_string())
                .collect::<Vec<_>>();
            if !matches!(challenge, ChallengeSettings::Dns01 { .. })
                && domains.iter().any(|d| d.starts_with("*."))
            {
                config.new_parse_error(
                    ("acme", acme_id, "domains"),
                    "Wildcard domains are only supported with DNS-01 challenge",
                );
                continue 'outer;
            }

            // This ACME manager is the default when SNI is not available
            let default = config
                .property::<bool>(("acme", acme_id, "default"))
                .unwrap_or_default();

            // Add domains for self-signed certificate
            subject_names.extend(domains.iter().cloned());

            if !domains.is_empty() {
                match AcmeProvider::new(
                    acme_id.to_string(),
                    directory,
                    domains,
                    contact,
                    challenge,
                    renew_before,
                    default,
                ) {
                    Ok(acme_provider) => {
                        acme_providers.insert(acme_id.to_string(), acme_provider);
                    }
                    Err(err) => {
                        config.new_build_error(format!("acme.{acme_id}"), err.to_string());
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

#[allow(clippy::unnecessary_to_owned)]
fn build_dns_updater(config: &mut Config, acme_id: &str) -> Option<DnsUpdater> {
    match config.value_require(("acme", acme_id, "provider"))? {
        "rfc2136-tsig" => {
            let algorithm: TsigAlgorithm = config
                .value_require(("acme", acme_id, "tsig-algorithm"))?
                .parse()
                .map_err(|_| {
                    config.new_parse_error(("acme", acme_id, "tsig-algorithm"), "Invalid algorithm")
                })
                .ok()?;
            let key = STANDARD
                .decode(config.value_require(("acme", acme_id, "secret"))?.trim())
                .map_err(|_| {
                    config.new_parse_error(
                        ("acme", acme_id, "secret"),
                        "Failed to base64 decode secret",
                    )
                })
                .ok()?;
            let host = config.property_require::<IpAddr>(("acme", acme_id, "host"))?;
            let port = config
                .property_or_default::<u16>(("acme", acme_id, "port"), "53")
                .unwrap_or(53);
            let addr = if config.value(("acme", acme_id, "protocol")) == Some("tcp") {
                DnsAddress::Tcp(SocketAddr::new(host, port))
            } else {
                DnsAddress::Udp(SocketAddr::new(host, port))
            };

            DnsUpdater::new_rfc2136_tsig(
                addr,
                config
                    .value_require(("acme", acme_id, "key"))?
                    .trim()
                    .to_string(),
                key,
                algorithm,
            )
            .map_err(|err| {
                config.new_build_error(
                    ("acme", acme_id, "provider"),
                    format!("Failed to create RFC2136-TSIG DNS updater: {err}"),
                )
            })
            .ok()
        }
        "cloudflare" => {
            let timeout = config
                .property_or_default(("acme", acme_id, "timeout"), "30s")
                .unwrap_or_else(|| Duration::from_secs(30));

            DnsUpdater::new_cloudflare(
                config
                    .value_require(("acme", acme_id, "secret"))?
                    .trim()
                    .to_string(),
                config.value(("acme", acme_id, "user")).map(|s| s.trim()),
                timeout.into(),
            )
            .map_err(|err| {
                config.new_build_error(
                    ("acme", acme_id, "provider"),
                    format!("Failed to create Cloudflare DNS updater: {err}"),
                )
            })
            .ok()
        }
        _ => {
            config.new_parse_error(("acme", acme_id, "provider"), "Unsupported provider");
            None
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

pub(crate) fn build_certified_key(cert: Vec<u8>, pk: Vec<u8>) -> Result<CertifiedKey, String> {
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
) -> Result<CertifiedKey, String> {
    let cert = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
    )
}
