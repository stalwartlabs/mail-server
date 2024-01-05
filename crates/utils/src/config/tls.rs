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

use std::{io::Cursor, path::PathBuf, sync::Arc, time::Duration};

use ahash::AHashMap;
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

use crate::{
    acme::{directory::LETS_ENCRYPT_PRODUCTION_DIRECTORY, AcmeManager},
    listener::tls::Certificate,
};

use super::Config;

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

impl Config {
    pub fn parse_certificates(&self) -> super::Result<AHashMap<String, Arc<Certificate>>> {
        let mut certs = AHashMap::new();
        for cert_id in self.sub_keys("certificate") {
            let key_cert = ("certificate", cert_id, "cert");
            let key_pk = ("certificate", cert_id, "private-key");

            let mut cert = Certificate {
                cert: ArcSwap::from(Arc::new(build_certified_key(
                    self.file_contents(key_cert)?,
                    self.file_contents(key_pk)?,
                    &format!("certificate.{cert_id}"),
                )?)),
                path: Vec::with_capacity(2),
            };

            for key in [key_cert, key_pk] {
                if let Some(path) = self.value(key).and_then(|v| v.strip_prefix("file://")) {
                    cert.path.push(PathBuf::from(path));
                }
            }

            certs.insert(cert_id.to_string(), Arc::new(cert));
        }

        Ok(certs)
    }

    pub fn parse_acmes(&self) -> super::Result<AHashMap<String, Arc<AcmeManager>>> {
        let mut acmes = AHashMap::new();
        for acme_id in self.sub_keys("acme") {
            let directory = self
                .value(("acme", acme_id, "directory"))
                .unwrap_or(LETS_ENCRYPT_PRODUCTION_DIRECTORY)
                .trim()
                .to_string();
            let contact = self
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
            let cache = PathBuf::from(self.value_require(("acme", acme_id, "cache"))?);
            if !cache.exists() {
                std::fs::create_dir_all(&cache).map_err(|err| {
                    format!("Failed to create ACME cache directory {:?}: {}", cache, err)
                })?;
            }

            let renew_before: Duration =
                self.property_or_static(("acme", acme_id, "renew-before"), "30d")?;

            if directory.is_empty() {
                return Err(format!("Missing directory for acme.{acme_id}."));
            }

            if contact.is_empty() {
                return Err(format!("Missing contact for acme.{acme_id}."));
            }

            // Find which domains are covered by this ACME manager
            let mut domains = Vec::new();
            for id in self.sub_keys("server.listener") {
                match (
                    self.value_or_default(("server.listener", id, "tls.acme"), "server.tls.acme"),
                    self.value_or_default(("server.listener", id, "hostname"), "server.hostname"),
                ) {
                    (Some(listener_acme), Some(hostname)) if listener_acme == acme_id => {
                        let hostname = hostname.trim().to_lowercase();

                        if !domains.contains(&hostname) {
                            domains.push(hostname);
                        }
                    }
                    _ => (),
                }
            }

            acmes.insert(
                acme_id.to_string(),
                Arc::new(AcmeManager::new(
                    directory,
                    domains,
                    contact,
                    renew_before,
                    cache,
                )?),
            );
        }

        Ok(acmes)
    }
}

pub(crate) fn build_certified_key(
    cert: Vec<u8>,
    pk: Vec<u8>,
    id: &str,
) -> super::Result<CertifiedKey> {
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates in {id:?}: {err}"))?;
    if cert.is_empty() {
        return Err(format!("No certificates found in {id:?}."));
    }
    let pk = match read_one(&mut Cursor::new(pk))
        .map_err(|err| format!("Failed to read private keys in {id:?}.: {err}",))?
        .into_iter()
        .next()
    {
        Some(Item::Pkcs8Key(key)) => PrivateKeyDer::Pkcs8(key),
        Some(Item::Pkcs1Key(key)) => PrivateKeyDer::Pkcs1(key),
        Some(Item::Sec1Key(key)) => PrivateKeyDer::Sec1(key),
        Some(_) => return Err(format!("Unsupported private keys found in {id:?}.",)),
        None => return Err(format!("No private keys found in {id:?}.",)),
    };

    Ok(CertifiedKey {
        cert,
        key: any_supported_type(&pk)
            .map_err(|err| format!("Failed to sign certificate for {id:?}: {err}",))?,
        ocsp: None,
    })
}

pub(crate) fn build_self_signed_cert(domains: &[String]) -> super::Result<CertifiedKey> {
    let cert = generate_simple_self_signed(domains).map_err(|err| {
        format!(
            "Failed to generate self-signed certificate for {domains:?}: {err}",
            domains = domains
        )
    })?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
        "self-signed",
    )
}
