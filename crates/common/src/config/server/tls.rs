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

use std::{io::Cursor, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use rcgen::generate_simple_self_signed;
use rustls::{
    client::verify_server_name,
    crypto::ring::sign::any_supported_type,
    server::ParsedCertificate,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    Error, SupportedProtocolVersion,
};
use rustls_pemfile::{certs, read_one, Item};
use rustls_pki_types::{DnsName, PrivateKeyDer, ServerName};
use utils::config::Config;

use crate::{
    listener::{
        acme::{directory::LETS_ENCRYPT_PRODUCTION_DIRECTORY, AcmeManager},
        tls::Certificate,
    },
    ConfigBuilder,
};

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

impl ConfigBuilder {
    pub fn parse_certificates(&mut self, config: &mut Config) {
        let cert_ids = config
            .sub_keys("certificate", ".cert")
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        for cert_id in cert_ids {
            let cert_id = cert_id.as_str();
            let key_cert = ("certificate", cert_id, "cert");
            let key_pk = ("certificate", cert_id, "private-key");

            let cert = config
                .value_require_(key_cert)
                .map(|s| s.as_bytes().to_vec());
            let pk = config.value_require_(key_pk).map(|s| s.as_bytes().to_vec());

            if let (Some(cert), Some(pk)) = (cert, pk) {
                match build_certified_key(cert, pk) {
                    Ok(cert) => {
                        // Parse alternative names
                        let subjects = config
                            .values(("certificate", cert_id, "sni-subjects"))
                            .map(|(_, v)| v.to_string())
                            .collect::<Vec<_>>();
                        let mut sni_names = Vec::new();
                        for subject in subjects {
                            match DnsName::try_from(subject)
                                .map_err(|_| Error::General("Bad DNS name".into()))
                                .map(|name| ServerName::DnsName(name.to_lowercase_owned()))
                                .and_then(|name| {
                                    cert.end_entity_cert()
                                        .and_then(ParsedCertificate::try_from)
                                        .and_then(|cert| verify_server_name(&cert, &name))
                                        .map(|_| name)
                                }) {
                                Ok(ServerName::DnsName(server_name)) => {
                                    sni_names.push(server_name.as_ref().to_string());
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    config.new_parse_error(
                                        ("certificate", cert_id, "sni-subjects"),
                                        err.to_string(),
                                    );
                                }
                            }
                        }

                        let cert = Arc::new(Certificate {
                            cert: ArcSwap::from(Arc::new(cert)),
                            cert_id: cert_id.to_string(),
                        });

                        for sni_name in sni_names {
                            self.certificates_sni.insert(sni_name, cert.clone());
                        }

                        self.certificates.insert(cert_id.to_string(), cert);
                    }
                    Err(err) => config.new_build_error(format!("certificate.{cert_id}"), err),
                }
            }
        }
    }

    pub fn parse_acmes(&mut self, config: &mut Config) {
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
                .property_or_default_(("acme", acme_id.as_str(), "renew-before"), "30d")
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

            if !domains.is_empty() {
                match AcmeManager::new(
                    acme_id.to_string(),
                    directory,
                    domains,
                    contact,
                    renew_before,
                    self.core.storage.data.clone(),
                ) {
                    Ok(acme_manager) => {
                        self.acme_managers
                            .insert(acme_id.to_string(), Arc::new(acme_manager));
                    }
                    Err(err) => {
                        config.new_build_error(format!("acme.{acme_id}"), err);
                    }
                }
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

pub(crate) fn build_self_signed_cert(domains: &[String]) -> utils::config::Result<CertifiedKey> {
    let cert = generate_simple_self_signed(domains).map_err(|err| {
        format!(
            "Failed to generate self-signed certificate for {domains:?}: {err}",
            domains = domains
        )
    })?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
    )
}
