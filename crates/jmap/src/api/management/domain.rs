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

use directory::backend::internal::manage::ManageDirectory;

use hyper::Method;
use jmap_proto::error::request::RequestError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::Digest;
use store::ahash::AHashMap;
use utils::url_params::UrlParams;
use x509_parser::parse_x509_certificate;

use crate::{
    api::{
        http::ToHttpResponse,
        management::dkim::{obtain_dkim_public_key, Algorithm},
        HttpRequest, HttpResponse, JsonResponse,
    },
    JMAP,
};

use super::decode_path_element;

#[derive(Debug, Serialize, Deserialize)]
struct DnsRecord {
    #[serde(rename = "type")]
    typ: String,
    name: String,
    content: String,
}

impl JMAP {
    pub async fn handle_manage_domain(&self, req: &HttpRequest, path: Vec<&str>) -> HttpResponse {
        match (path.get(1), req.method()) {
            (None, &Method::GET) => {
                // List domains
                let params = UrlParams::new(req.uri().query());
                let filter = params.get("filter");
                let page: usize = params.parse("page").unwrap_or(0);
                let limit: usize = params.parse("limit").unwrap_or(0);

                match self.core.storage.data.list_domains(filter).await {
                    Ok(domains) => {
                        let (total, domains) = if limit > 0 {
                            let offset = page.saturating_sub(1) * limit;
                            (
                                domains.len(),
                                domains.into_iter().skip(offset).take(limit).collect(),
                            )
                        } else {
                            (domains.len(), domains)
                        };

                        JsonResponse::new(json!({
                                "data": {
                                    "items": domains,
                                    "total": total,
                                },
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (Some(domain), &Method::GET) => {
                // Obtain DNS records
                let domain = decode_path_element(domain);
                match self.build_dns_records(domain.as_ref()).await {
                    Ok(records) => JsonResponse::new(json!({
                        "data": records,
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }
            (Some(domain), &Method::POST) => {
                // Create domain
                let domain = decode_path_element(domain);
                match self.core.storage.data.create_domain(domain.as_ref()).await {
                    Ok(_) => {
                        // Set default domain name if missing
                        if matches!(
                            self.core.storage.config.get("lookup.default.domain").await,
                            Ok(None)
                        ) {
                            if let Err(err) = self
                                .core
                                .storage
                                .config
                                .set([("lookup.default.domain", domain.as_ref())])
                                .await
                            {
                                tracing::error!("Failed to set default domain name: {}", err);
                            }
                        }

                        JsonResponse::new(json!({
                            "data": (),
                        }))
                        .into_http_response()
                    }
                    Err(err) => err.into_http_response(),
                }
            }
            (Some(domain), &Method::DELETE) => {
                // Delete domain
                let domain = decode_path_element(domain);
                match self.core.storage.data.delete_domain(domain.as_ref()).await {
                    Ok(_) => JsonResponse::new(json!({
                        "data": (),
                    }))
                    .into_http_response(),
                    Err(err) => err.into_http_response(),
                }
            }

            _ => RequestError::not_found().into_http_response(),
        }
    }

    async fn build_dns_records(&self, domain_name: &str) -> store::Result<Vec<DnsRecord>> {
        // Obtain server name
        let server_name = self
            .core
            .storage
            .config
            .get("lookup.default.hostname")
            .await?
            .unwrap_or_else(|| "localhost".to_string());
        let mut records = Vec::new();

        // Obtain DKIM keys
        let mut keys = AHashMap::new();
        let mut signature_ids = Vec::new();
        for (key, value) in self.core.storage.config.list("signature.", true).await? {
            match key.strip_suffix(".domain") {
                Some(key_id) if value == domain_name => {
                    signature_ids.push(key_id.to_string());
                }
                _ => (),
            }
            keys.insert(key, value);
        }

        // Add MX and CNAME records
        records.push(DnsRecord {
            typ: "MX".to_string(),
            name: format!("{domain_name}."),
            content: format!("10 {server_name}."),
        });
        if server_name
            .strip_prefix("mail.")
            .map_or(true, |s| s != domain_name)
        {
            records.push(DnsRecord {
                typ: "CNAME".to_string(),
                name: format!("mail.{domain_name}."),
                content: format!("{server_name}."),
            });
        }

        // Process DKIM keys
        for signature_id in signature_ids {
            if let (Some(algo), Some(pk), Some(selector)) = (
                keys.get(&format!("{signature_id}.algorithm"))
                    .and_then(|algo| algo.parse::<Algorithm>().ok()),
                keys.get(&format!("{signature_id}.private-key")),
                keys.get(&format!("{signature_id}.selector")),
            ) {
                match obtain_dkim_public_key(algo, pk) {
                    Ok(public) => {
                        records.push(DnsRecord {
                            typ: "TXT".to_string(),
                            name: format!("{selector}._domainkey.{domain_name}.",),
                            content: match algo {
                                Algorithm::Rsa => format!("v=DKIM1; k=rsa; h=sha256; p={public}"),
                                Algorithm::Ed25519 => {
                                    format!("v=DKIM1; k=ed25519; h=sha256; p={public}")
                                }
                            },
                        });
                    }
                    Err(err) => {
                        tracing::debug!("Failed to obtain DKIM public key: {}", err);
                    }
                }
            }
        }

        // Add SPF records
        if server_name.ends_with(&format!(".{domain_name}")) || server_name == domain_name {
            records.push(DnsRecord {
                typ: "TXT".to_string(),
                name: format!("{server_name}."),
                content: "v=spf1 a ra=postmaster -all".to_string(),
            });
        }
        records.push(DnsRecord {
            typ: "TXT".to_string(),
            name: format!("{domain_name}."),
            content: "v=spf1 mx ra=postmaster -all".to_string(),
        });

        let mut has_https = false;
        for (protocol, port, is_tls) in self
            .core
            .storage
            .config
            .get_services()
            .await
            .unwrap_or_default()
        {
            match (protocol.as_str(), port) {
                ("smtp", port @ 26..=u16::MAX) => {
                    records.push(DnsRecord {
                        typ: "SRV".to_string(),
                        name: format!(
                            "_submission{}._tcp.{domain_name}.",
                            if is_tls { "s" } else { "" }
                        ),
                        content: format!("0 1 {port} {server_name}."),
                    });
                }
                ("imap" | "pop3", port @ 1..=u16::MAX) => {
                    records.push(DnsRecord {
                        typ: "SRV".to_string(),
                        name: format!(
                            "_{protocol}{}._tcp.{domain_name}.",
                            if is_tls { "s" } else { "" }
                        ),
                        content: format!("0 1 {port} {server_name}."),
                    });
                }
                ("http", _) if is_tls => {
                    has_https = true;
                }
                _ => (),
            }
        }

        if has_https {
            // Add autoconfig and autodiscover records
            records.push(DnsRecord {
                typ: "CNAME".to_string(),
                name: format!("autoconfig.{domain_name}."),
                content: format!("{server_name}."),
            });
            records.push(DnsRecord {
                typ: "CNAME".to_string(),
                name: format!("autodiscover.{domain_name}."),
                content: format!("{server_name}."),
            });

            // Add MTA-STS records
            if let Some(policy) = self.core.build_mta_sts_policy() {
                records.push(DnsRecord {
                    typ: "CNAME".to_string(),
                    name: format!("mta-sts.{domain_name}."),
                    content: format!("{server_name}."),
                });
                records.push(DnsRecord {
                    typ: "TXT".to_string(),
                    name: format!("_mta-sts.{domain_name}."),
                    content: format!("v=STSv1; id={}", policy.id),
                });
            }
        }

        // Add DMARC records
        records.push(DnsRecord {
            typ: "TXT".to_string(),
            name: format!("_dmarc.{domain_name}."),
            content: format!("v=DMARC1; p=reject; rua=mailto:postmaster@{domain_name}; ruf=mailto:postmaster@{domain_name}",),
        });

        // Add TLSA records
        for (name, key) in self.core.tls.certificates.load().iter() {
            if !name.ends_with(domain_name)
                || name.starts_with("mta-sts.")
                || name.starts_with("autoconfig.")
                || name.starts_with("autodiscover.")
            {
                continue;
            }

            for (cert_num, cert) in key.cert.iter().enumerate() {
                let parsed_cert = match parse_x509_certificate(cert) {
                    Ok((_, parsed_cert)) => parsed_cert,
                    Err(err) => {
                        tracing::debug!("Failed to parse certificate: {}", err);
                        continue;
                    }
                };

                let name = if !name.starts_with('.') {
                    format!("_25._tcp.{name}.")
                } else {
                    format!("_25._tcp.mail.{name}.")
                };
                let cu = if cert_num == 0 { 3 } else { 2 };

                for (s, cert) in [cert, parsed_cert.subject_pki.raw].into_iter().enumerate() {
                    for (m, hash) in [
                        format!("{:x}", sha2::Sha256::digest(cert)),
                        format!("{:x}", sha2::Sha512::digest(cert)),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        records.push(DnsRecord {
                            typ: "TLSA".to_string(),
                            name: name.clone(),
                            content: format!("{} {} {} {}", cu, s, m + 1, hash),
                        });
                    }
                }
            }
        }

        Ok(records)
    }
}
