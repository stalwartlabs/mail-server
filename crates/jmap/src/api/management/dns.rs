/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{auth::AccessToken, Server};
use directory::{
    backend::internal::manage::{self},
    Permission,
};

use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::Digest;
use utils::config::Config;
use x509_parser::parse_x509_certificate;

use crate::api::{
    http::ToHttpResponse,
    management::dkim::{obtain_dkim_public_key, Algorithm},
    HttpRequest, HttpResponse, JsonResponse,
};

use super::decode_path_element;
use std::future::Future;

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    typ: String,
    class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    name: String,
    content: String,
}

pub trait DnsManagement: Sync + Send {
    fn handle_manage_dns(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn build_dns_records(
        &self,
        domain_name: &str,
    ) -> impl Future<Output = trc::Result<Vec<DnsRecord>>> + Send;
}

impl DnsManagement for Server {
    async fn handle_manage_dns(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2),
            req.method(),
        ) {
            ("records", Some(domain), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::DomainGet)?;

                // Obtain DNS records
                let domain = decode_path_element(domain);
                Ok(JsonResponse::new(json!({
                    "data": self.build_dns_records(domain.as_ref()).await?,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn build_dns_records(&self, domain_name: &str) -> trc::Result<Vec<DnsRecord>> {
        // Obtain server name
        let server_name = if domain_name == self.core.network.server_name {
            "@".to_string()
        } else {
            self.core
                .network
                .server_name
                .strip_suffix(&format!(".{domain_name}"))
                .map_or_else(
                    || format!("{}.", &self.core.network.server_name),
                    |s| s.to_string(),
                )
        };
        let mut records = Vec::new();

        // Obtain DKIM keys
        let mut keys = Config::default();
        let mut signature_ids = Vec::new();
        let mut has_macros = false;
        for (key, value) in self.core.storage.config.list("signature.", true).await? {
            match key.strip_suffix(".domain") {
                Some(key_id) if value == domain_name => {
                    signature_ids.push(key_id.to_string());
                }
                _ => (),
            }
            if !has_macros && value.contains("%{") {
                has_macros = true;
            }
            keys.keys.insert(key, value);
        }

        // Add MX and CNAME records
        records.push(DnsRecord {
            typ: "MX".to_string(),
            class: "IN".to_string(),
            ttl: None,
            name: "@".to_string(),
            content: format!("10 {server_name}"),
        });
        if server_name != "mail" {
            records.push(DnsRecord {
                typ: "CNAME".to_string(),
                class: "IN".to_string(),
                ttl: None,
                name: "mail".to_string(),
                content: server_name.clone(),
            });
        }

        // Process DKIM keys
        if has_macros {
            keys.resolve_macros(&["env", "file", "cfg"]).await;
            keys.log_errors();
        }
        for signature_id in signature_ids {
            if let (Some(algo), Some(pk), Some(selector)) = (
                keys.value(format!("{signature_id}.algorithm"))
                    .and_then(|algo| algo.parse::<Algorithm>().ok()),
                keys.value(format!("{signature_id}.private-key")),
                keys.value(format!("{signature_id}.selector")),
            ) {
                match obtain_dkim_public_key(algo, pk) {
                    Ok(public) => {
                        records.push(DnsRecord {
                            typ: "TXT".to_string(),
                            class: "IN".to_string(),
                            ttl: None,
                            name: format!("{selector}._domainkey",),
                            content: match algo {
                                Algorithm::Rsa => format!("v=DKIM1; k=rsa; h=sha256; p={public}"),
                                Algorithm::Ed25519 => {
                                    format!("v=DKIM1; k=ed25519; h=sha256; p={public}")
                                }
                            },
                        });
                    }
                    Err(err) => {
                        trc::error!(err);
                    }
                }
            }
        }

        // Add SPF records
        if !server_name.ends_with(".") {
            records.push(DnsRecord {
                typ: "TXT".to_string(),
                class: "IN".to_string(),
                ttl: None,
                name: server_name.clone(),
                content: "v=spf1 a ra=postmaster -all".to_string(),
            });
        }
        records.push(DnsRecord {
            typ: "TXT".to_string(),
            class: "IN".to_string(),
            ttl: None,
            name: "@".to_string(),
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
                        class: "IN".to_string(),
                        ttl: None,
                        name: format!("_submission{}._tcp", if is_tls { "s" } else { "" }),
                        content: format!("0 1 {port} {server_name}"),
                    });
                }
                ("imap" | "pop3", port @ 1..=u16::MAX) => {
                    records.push(DnsRecord {
                        typ: "SRV".to_string(),
                        class: "IN".to_string(),
                        ttl: None,
                        name: format!("_{protocol}{}._tcp", if is_tls { "s" } else { "" }),
                        content: format!("0 1 {port} {server_name}"),
                    });
                }
                ("http", _) if is_tls => {
                    has_https = true;
                    records.push(DnsRecord {
                        typ: "SRV".to_string(),
                        class: "IN".to_string(),
                        ttl: None,
                        name: "_jmap._tcp".to_string(),
                        content: format!("0 1 {port} {server_name}"),
                    });
                }
                _ => (),
            }
        }

        if has_https {
            // Add autoconfig and autodiscover records
            if server_name != "autoconfig" {
                records.push(DnsRecord {
                    typ: "CNAME".to_string(),
                    class: "IN".to_string(),
                    ttl: None,
                    name: "autoconfig".to_string(),
                    content: server_name.clone(),
                });
            }
            if server_name != "autodiscover" {
                records.push(DnsRecord {
                    typ: "CNAME".to_string(),
                    class: "IN".to_string(),
                    ttl: None,
                    name: "autodiscover".to_string(),
                    content: server_name.clone(),
                });
            }

            // Add MTA-STS records
            if let Some(policy) = self.build_mta_sts_policy() {
                if server_name != "mta-sts" {
                    records.push(DnsRecord {
                        typ: "CNAME".to_string(),
                        class: "IN".to_string(),
                        ttl: None,
                        name: "mta-sts".to_string(),
                        content: server_name.clone(),
                    });
                }
                records.push(DnsRecord {
                    typ: "TXT".to_string(),
                    class: "IN".to_string(),
                    ttl: None,
                    name: "_mta-sts".to_string(),
                    content: format!("v=STSv1; id={}", policy.id),
                });
            }
        }

        // Add DMARC record
        records.push(DnsRecord {
            typ: "TXT".to_string(),
            class: "IN".to_string(),
            ttl: None,
            name: "_dmarc".to_string(),
            content: format!("v=DMARC1; p=reject; rua=mailto:postmaster@{domain_name}; ruf=mailto:postmaster@{domain_name}",),
        });

        // Add TLS reporting record
        records.push(DnsRecord {
            typ: "TXT".to_string(),
            class: "IN".to_string(),
            ttl: None,
            name: "_smtp._tls".to_string(),
            content: format!("v=TLSRPTv1; rua=mailto:postmaster@{domain_name}",),
        });

        // Add TLSA records
        for (name, key) in self.inner.data.tls_certificates.load().iter() {
            let tlsa_name = if name == domain_name {
                "@"
            } else if let Some(sub) = name.strip_suffix(&format!(".{domain_name}")) {
                sub
            } else {
                continue;
            };
            if tlsa_name == "mta-sts" || tlsa_name == "autoconfig" || tlsa_name == "autodiscover" {
                continue;
            }

            for (cert_num, cert) in key.cert.iter().enumerate() {
                let parsed_cert = match parse_x509_certificate(cert) {
                    Ok((_, parsed_cert)) => parsed_cert,
                    Err(err) => {
                        trc::error!(manage::error(
                            "Failed to parse certificate",
                            err.to_string().into()
                        ));
                        continue;
                    }
                };

                let name = if tlsa_name == "@" {
                    "_25._tcp".to_string()
                } else {
                    format!("_25._tcp.{tlsa_name}")
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
                            class: "IN".to_string(),
                            ttl: None,
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
