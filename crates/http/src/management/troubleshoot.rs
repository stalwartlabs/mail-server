/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use common::{
    Server,
    auth::{AccessToken, oauth::GrantType},
    config::smtp::resolver::{Policy, Tlsa},
    psl,
};
use directory::backend::internal::manage;
use http_body_util::{StreamBody, combinators::BoxBody};
use hyper::{
    Method, StatusCode,
    body::{Bytes, Frame},
};
use mail_auth::{
    AuthenticatedMessage, DkimResult, DmarcResult, IpLookupStrategy, IprevOutput, IprevResult,
    SpfOutput, SpfResult,
    dmarc::{self, verify::DmarcParameters},
    mta_sts::TlsRpt,
    spf::verify::SpfParameters,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use smtp::outbound::{
    client::{SmtpClient, StartTlsResult},
    dane::{dnssec::TlsaLookup, verify::TlsaVerify},
    lookup::{DnsLookup, ToNextHop},
    mta_sts::{lookup::MtaStsLookup, verify::VerifyPolicy},
};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use utils::url_params::UrlParams;

use http_proto::{request::decode_path_element, *};

pub trait TroubleshootApi: Sync + Send {
    fn handle_troubleshoot_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl TroubleshootApi for Server {
    async fn handle_troubleshoot_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
        body: Option<Vec<u8>>,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());
        let account_id = access_token.primary_id();

        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2).copied(),
            req.method(),
        ) {
            ("token", None, &Method::GET) => {
                // Issue a live telemetry token valid for 60 seconds
                Ok(JsonResponse::new(json!({
                    "data": self.encode_access_token(GrantType::Troubleshoot, account_id,  "web", 60).await?,
            }))
            .into_http_response())
            }
            ("delivery", Some(target), &Method::GET) => {
                let timeout = Duration::from_secs(
                    params
                        .parse::<u64>("timeout")
                        .filter(|interval| *interval >= 1)
                        .unwrap_or(30),
                );

                let mut rx = spawn_delivery_troubleshoot(
                    self.clone(),
                    decode_path_element(target).to_lowercase(),
                    timeout,
                );

                Ok(HttpResponse::new(StatusCode::OK)
                    .with_content_type("text/event-stream")
                    .with_cache_control("no-store")
                    .with_stream_body(BoxBody::new(StreamBody::new(async_stream::stream! {
                        while let Some(stage) = rx.recv().await {
                            yield Ok(stage.to_frame());
                        }
                        yield Ok(DeliveryStage::Completed.to_frame());
                    }))))
            }
            ("dmarc", None, &Method::POST) => {
                let request = serde_json::from_slice::<DmarcTroubleshootRequest>(
                    body.as_deref().unwrap_or_default(),
                )
                .map_err(|err| {
                    trc::EventType::Resource(trc::ResourceEvent::BadParameters).from_json_error(err)
                })?;
                let response = dmarc_troubleshoot(self, request).await.ok_or_else(|| {
                    manage::error(
                        "Invalid message body",
                        "Failed to parse message body".into(),
                    )
                })?;

                Ok(JsonResponse::new(json!({
                        "data": response,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
enum DeliveryStage {
    MxLookupStart {
        domain: String,
    },
    MxLookupSuccess {
        mxs: Vec<MX>,
        elapsed: u64,
    },
    MxLookupError {
        reason: String,
        elapsed: u64,
    },
    MtaStsFetchStart,
    MtaStsFetchSuccess {
        policy: Policy,
        elapsed: u64,
    },
    MtaStsFetchError {
        reason: String,
        elapsed: u64,
    },
    MtaStsNotFound {
        elapsed: u64,
    },
    TlsRptLookupStart,
    TlsRptLookupSuccess {
        rua: Vec<ReportUri>,
        elapsed: u64,
    },
    TlsRptLookupError {
        reason: String,
        elapsed: u64,
    },
    TlsRptNotFound {
        elapsed: u64,
    },
    DeliveryAttemptStart {
        hostname: String,
    },
    MtaStsVerifySuccess,
    MtaStsVerifyError {
        reason: String,
    },
    TlsaLookupStart,
    TlsaLookupSuccess {
        record: Tlsa,
        elapsed: u64,
    },
    TlsaNotFound {
        elapsed: u64,
        reason: String,
    },
    TlsaLookupError {
        elapsed: u64,
        reason: String,
    },
    IpLookupStart,
    IpLookupSuccess {
        remote_ips: Vec<IpAddr>,
        elapsed: u64,
    },
    IpLookupError {
        reason: String,
        elapsed: u64,
    },
    ConnectionStart {
        remote_ip: IpAddr,
    },
    ConnectionSuccess {
        elapsed: u64,
    },
    ConnectionError {
        elapsed: u64,
        reason: String,
    },
    ReadGreetingStart,
    ReadGreetingSuccess {
        elapsed: u64,
    },
    ReadGreetingError {
        elapsed: u64,
        reason: String,
    },
    EhloStart,
    EhloSuccess {
        elapsed: u64,
    },
    EhloError {
        elapsed: u64,
        reason: String,
    },
    StartTlsStart,
    StartTlsSuccess {
        elapsed: u64,
    },
    StartTlsError {
        elapsed: u64,
        reason: String,
    },
    DaneVerifySuccess,
    DaneVerifyError {
        reason: String,
    },
    MailFromStart,
    MailFromSuccess {
        elapsed: u64,
    },
    MailFromError {
        reason: String,
        elapsed: u64,
    },
    RcptToStart,
    RcptToSuccess {
        elapsed: u64,
    },
    RcptToError {
        reason: String,
        elapsed: u64,
    },
    QuitStart,
    QuitCompleted {
        elapsed: u64,
    },
    Completed,
}

#[derive(Debug, Serialize, Deserialize)]
struct MX {
    pub exchanges: Vec<String>,
    pub preference: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum ReportUri {
    Mail { email: String },
    Http { url: String },
}

impl DeliveryStage {
    fn to_frame(&self) -> Frame<Bytes> {
        let payload = format!(
            "event: event\ndata: [{}]\n\n",
            serde_json::to_string(self).unwrap_or_default()
        );
        Frame::data(Bytes::from(payload))
    }
}

trait ElapsedMs {
    fn elapsed_ms(&self) -> u64;
}

impl ElapsedMs for Instant {
    fn elapsed_ms(&self) -> u64 {
        self.elapsed().as_millis() as u64
    }
}
fn spawn_delivery_troubleshoot(
    server: Server,
    domain_or_email: String,
    timeout: Duration,
) -> mpsc::Receiver<DeliveryStage> {
    let (tx, rx) = mpsc::channel(10);

    tokio::spawn(async move {
        let _ = delivery_troubleshoot(tx, server, domain_or_email, timeout).await;
    });

    rx
}

async fn delivery_troubleshoot(
    tx: mpsc::Sender<DeliveryStage>,
    server: Server,
    domain_or_email: String,
    timeout: Duration,
) -> Result<(), mpsc::error::SendError<DeliveryStage>> {
    let (domain, email) = if let Some((_, domain)) = domain_or_email.rsplit_once('@') {
        (domain.to_string(), Some(domain_or_email))
    } else {
        (domain_or_email, None)
    };

    let local_host = &server.core.network.server_name;

    tx.send(DeliveryStage::MxLookupStart {
        domain: domain.to_string(),
    })
    .await?;

    // Lookup MX
    let now = Instant::now();
    let mxs = match server
        .core
        .smtp
        .resolvers
        .dns
        .mx_lookup(&domain, Some(&server.inner.cache.dns_mx))
        .await
    {
        Ok(mxs) => mxs,
        Err(err) => {
            tx.send(DeliveryStage::MxLookupError {
                reason: err.to_string(),
                elapsed: now.elapsed_ms(),
            })
            .await?;

            return Ok(());
        }
    };

    // Obtain remote host list
    let hosts = if let Some(hosts) = mxs.to_remote_hosts(&domain, mxs.len()) {
        tx.send(DeliveryStage::MxLookupSuccess {
            mxs: mxs
                .iter()
                .map(|mx| MX {
                    exchanges: mx.exchanges.clone(),
                    preference: mx.preference,
                })
                .collect(),
            elapsed: now.elapsed_ms(),
        })
        .await?;

        hosts
    } else {
        tx.send(DeliveryStage::MxLookupError {
            reason: "Null MX record".to_string(),
            elapsed: now.elapsed_ms(),
        })
        .await?;

        return Ok(());
    };

    // Fetch MTA-STS policy
    let now = Instant::now();
    tx.send(DeliveryStage::MtaStsFetchStart).await?;
    let mta_sts_policy = match server.lookup_mta_sts_policy(&domain, timeout).await {
        Ok(policy) => {
            tx.send(DeliveryStage::MtaStsFetchSuccess {
                policy: policy.as_ref().clone(),
                elapsed: now.elapsed_ms(),
            })
            .await?;
            Some(policy)
        }
        Err(err) => {
            if matches!(
                &err,
                smtp::outbound::mta_sts::Error::Dns(mail_auth::Error::DnsRecordNotFound(_))
            ) {
                tx.send(DeliveryStage::MtaStsNotFound {
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            } else {
                tx.send(DeliveryStage::MtaStsFetchError {
                    reason: err.to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
            None
        }
    };

    // Fetch TLS-RPT settings
    let now = Instant::now();
    tx.send(DeliveryStage::TlsRptLookupStart).await?;
    match server
        .core
        .smtp
        .resolvers
        .dns
        .txt_lookup::<TlsRpt>(
            format!("_smtp._tls.{domain}."),
            Some(&server.inner.cache.dns_txt),
        )
        .await
    {
        Ok(record) => {
            tx.send(DeliveryStage::TlsRptLookupSuccess {
                rua: record
                    .rua
                    .iter()
                    .map(|r| match r {
                        mail_auth::mta_sts::ReportUri::Mail(email) => ReportUri::Mail {
                            email: email.clone(),
                        },
                        mail_auth::mta_sts::ReportUri::Http(url) => {
                            ReportUri::Http { url: url.clone() }
                        }
                    })
                    .collect(),
                elapsed: now.elapsed_ms(),
            })
            .await?;
        }
        Err(err) => {
            if matches!(&err, mail_auth::Error::DnsRecordNotFound(_)) {
                tx.send(DeliveryStage::TlsRptNotFound {
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            } else {
                tx.send(DeliveryStage::TlsRptLookupError {
                    reason: err.to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
        }
    }

    // Try with each host
    'outer: for host in hosts {
        let hostname = host.hostname();

        tx.send(DeliveryStage::DeliveryAttemptStart {
            hostname: hostname.to_string(),
        })
        .await?;

        // Verify MTA-STS policy
        if let Some(mta_sts_policy) = &mta_sts_policy {
            if mta_sts_policy.verify(hostname) {
                tx.send(DeliveryStage::MtaStsVerifySuccess).await?;
            } else {
                tx.send(DeliveryStage::MtaStsVerifyError {
                    reason: "Not authorized by policy".to_string(),
                })
                .await?;

                continue;
            }
        }

        // Fetch TLSA record
        tx.send(DeliveryStage::TlsaLookupStart).await?;

        let now = Instant::now();
        let dane_policy = match server.tlsa_lookup(format!("_25._tcp.{hostname}.")).await {
            Ok(Some(tlsa)) if tlsa.has_end_entities => {
                tx.send(DeliveryStage::TlsaLookupSuccess {
                    record: tlsa.as_ref().clone(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;

                Some(tlsa)
            }
            Ok(Some(_)) => {
                tx.send(DeliveryStage::TlsaLookupError {
                    elapsed: now.elapsed_ms(),
                    reason: "TLSA record does not have end entities".to_string(),
                })
                .await?;

                None
            }
            Ok(None) => {
                tx.send(DeliveryStage::TlsaNotFound {
                    elapsed: now.elapsed_ms(),
                    reason: "No TLSA DNSSEC records found".to_string(),
                })
                .await?;

                None
            }
            Err(err) => {
                if matches!(&err, mail_auth::Error::DnsRecordNotFound(_)) {
                    tx.send(DeliveryStage::TlsaNotFound {
                        elapsed: now.elapsed_ms(),
                        reason: "No TLSA records found for MX".to_string(),
                    })
                    .await?;
                } else {
                    tx.send(DeliveryStage::TlsaLookupError {
                        elapsed: now.elapsed_ms(),
                        reason: err.to_string(),
                    })
                    .await?;
                }
                None
            }
        };

        tx.send(DeliveryStage::IpLookupStart).await?;

        let now = Instant::now();
        match server
            .ip_lookup(
                host.fqdn_hostname().as_ref(),
                IpLookupStrategy::Ipv4thenIpv6,
                usize::MAX,
            )
            .await
        {
            Ok(remote_ips) if !remote_ips.is_empty() => {
                tx.send(DeliveryStage::IpLookupSuccess {
                    remote_ips: remote_ips.clone(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;

                for remote_ip in remote_ips {
                    // Start connection
                    tx.send(DeliveryStage::ConnectionStart { remote_ip })
                        .await?;

                    let now = Instant::now();
                    match SmtpClient::connect(SocketAddr::new(remote_ip, 25), timeout, 0).await {
                        Ok(mut client) => {
                            tx.send(DeliveryStage::ConnectionSuccess {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;

                            // Read greeting
                            tx.send(DeliveryStage::ReadGreetingStart).await?;

                            let now = Instant::now();
                            if let Err(status) = client.read_greeting(hostname).await {
                                tx.send(DeliveryStage::ReadGreetingError {
                                    elapsed: now.elapsed_ms(),
                                    reason: status.to_string(),
                                })
                                .await?;

                                continue;
                            }
                            tx.send(DeliveryStage::ReadGreetingSuccess {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;

                            // Say EHLO
                            tx.send(DeliveryStage::EhloStart).await?;

                            let now = Instant::now();
                            let capabilities = match tokio::time::timeout(timeout, async {
                                client
                                    .stream
                                    .write_all(format!("EHLO {local_host}\r\n",).as_bytes())
                                    .await?;
                                client.stream.flush().await?;
                                client.read_ehlo().await
                            })
                            .await
                            {
                                Ok(Ok(capabilities)) => {
                                    tx.send(DeliveryStage::EhloSuccess {
                                        elapsed: now.elapsed_ms(),
                                    })
                                    .await?;

                                    capabilities
                                }
                                Ok(Err(err)) => {
                                    tx.send(DeliveryStage::EhloError {
                                        elapsed: now.elapsed_ms(),
                                        reason: err.to_string(),
                                    })
                                    .await?;

                                    continue;
                                }
                                Err(_) => {
                                    tx.send(DeliveryStage::EhloError {
                                        elapsed: now.elapsed_ms(),
                                        reason: "Timed out reading response".to_string(),
                                    })
                                    .await?;

                                    continue;
                                }
                            };

                            // Start TLS
                            tx.send(DeliveryStage::StartTlsStart).await?;

                            let now = Instant::now();
                            let mut client = match client
                                .try_start_tls(
                                    &server.inner.data.smtp_connectors.pki_verify,
                                    hostname,
                                    &capabilities,
                                )
                                .await
                            {
                                StartTlsResult::Success { smtp_client } => {
                                    tx.send(DeliveryStage::StartTlsSuccess {
                                        elapsed: now.elapsed_ms(),
                                    })
                                    .await?;

                                    smtp_client
                                }
                                StartTlsResult::Error { error } => {
                                    tx.send(DeliveryStage::StartTlsError {
                                        elapsed: now.elapsed_ms(),
                                        reason: error.to_string(),
                                    })
                                    .await?;

                                    continue;
                                }
                                StartTlsResult::Unavailable { response, .. } => {
                                    tx.send(DeliveryStage::StartTlsError {
                                        elapsed: now.elapsed_ms(),
                                        reason: response.map(|r| r.to_string()).unwrap_or_else(
                                            || "STARTTLS not advertised by host".to_string(),
                                        ),
                                    })
                                    .await?;

                                    continue;
                                }
                            };

                            // Verify DANE policy
                            if let Some(dane_policy) = &dane_policy {
                                if let Err(err) = dane_policy.verify(
                                    0,
                                    hostname,
                                    client.tls_connection().peer_certificates(),
                                ) {
                                    tx.send(DeliveryStage::DaneVerifyError {
                                        reason: err.to_string(),
                                    })
                                    .await?;
                                } else {
                                    tx.send(DeliveryStage::DaneVerifySuccess).await?;
                                }
                            }

                            // Say EHLO again (some SMTP servers require this)
                            tx.send(DeliveryStage::EhloStart).await?;

                            let now = Instant::now();
                            match tokio::time::timeout(timeout, async {
                                client
                                    .stream
                                    .write_all(format!("EHLO {local_host}\r\n",).as_bytes())
                                    .await?;
                                client.stream.flush().await?;
                                client.read_ehlo().await
                            })
                            .await
                            {
                                Ok(Ok(_)) => {
                                    tx.send(DeliveryStage::EhloSuccess {
                                        elapsed: now.elapsed_ms(),
                                    })
                                    .await?;
                                }
                                Ok(Err(err)) => {
                                    tx.send(DeliveryStage::EhloError {
                                        elapsed: now.elapsed_ms(),
                                        reason: err.to_string(),
                                    })
                                    .await?;

                                    continue;
                                }
                                Err(_) => {
                                    tx.send(DeliveryStage::EhloError {
                                        elapsed: now.elapsed_ms(),
                                        reason: "Timed out reading response".to_string(),
                                    })
                                    .await?;

                                    continue;
                                }
                            }

                            // Verify recipient
                            let mut is_success = email.is_none();
                            if let Some(email) = &email {
                                // MAIL FROM
                                tx.send(DeliveryStage::MailFromStart).await?;

                                let now = Instant::now();

                                match client.cmd(b"MAIL FROM:<>\r\n").await.and_then(|r| {
                                    if r.is_positive_completion() {
                                        Ok(r)
                                    } else {
                                        Err(mail_send::Error::UnexpectedReply(r))
                                    }
                                }) {
                                    Ok(_) => {
                                        tx.send(DeliveryStage::MailFromSuccess {
                                            elapsed: now.elapsed_ms(),
                                        })
                                        .await?;

                                        // RCPT TO
                                        tx.send(DeliveryStage::RcptToStart).await?;

                                        let now = Instant::now();
                                        match client
                                            .cmd(format!("RCPT TO:<{email}>\r\n").as_bytes())
                                            .await
                                            .and_then(|r| {
                                                if r.is_positive_completion() {
                                                    Ok(r)
                                                } else {
                                                    Err(mail_send::Error::UnexpectedReply(r))
                                                }
                                            }) {
                                            Ok(_) => {
                                                is_success = true;
                                                tx.send(DeliveryStage::RcptToSuccess {
                                                    elapsed: now.elapsed_ms(),
                                                })
                                                .await?;
                                            }
                                            Err(err) => {
                                                tx.send(DeliveryStage::RcptToError {
                                                    reason: err.to_string(),
                                                    elapsed: now.elapsed_ms(),
                                                })
                                                .await?;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        tx.send(DeliveryStage::MailFromError {
                                            reason: err.to_string(),
                                            elapsed: now.elapsed_ms(),
                                        })
                                        .await?;
                                    }
                                }
                            }

                            // QUIT
                            tx.send(DeliveryStage::QuitStart).await?;

                            let now = Instant::now();
                            client.quit().await;
                            tx.send(DeliveryStage::QuitCompleted {
                                elapsed: now.elapsed_ms(),
                            })
                            .await?;

                            if is_success {
                                break 'outer;
                            }
                        }
                        Err(err) => {
                            tx.send(DeliveryStage::ConnectionError {
                                elapsed: now.elapsed_ms(),
                                reason: err.to_string(),
                            })
                            .await?;
                        }
                    }
                }
            }
            Ok(_) => {
                tx.send(DeliveryStage::IpLookupError {
                    reason: "No IP addresses found for host".to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
            Err(err) => {
                tx.send(DeliveryStage::IpLookupError {
                    reason: err.to_string(),
                    elapsed: now.elapsed_ms(),
                })
                .await?;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct DmarcTroubleshootRequest {
    #[serde(rename = "remoteIp")]
    remote_ip: IpAddr,
    #[serde(rename = "ehloDomain")]
    ehlo_domain: String,
    #[serde(rename = "mailFrom")]
    mail_from: String,
    body: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DmarcTroubleshootResponse {
    #[serde(rename = "spfEhloDomain")]
    spf_ehlo_domain: String,
    #[serde(rename = "spfEhloResult")]
    spf_ehlo_result: AuthResult,
    #[serde(rename = "spfMailFromDomain")]
    spf_mail_from_domain: String,
    #[serde(rename = "spfMailFromResult")]
    spf_mail_from_result: AuthResult,
    #[serde(rename = "ipRevResult")]
    ip_rev_result: AuthResult,
    #[serde(rename = "ipRevPtr")]
    ip_rev_ptr: Vec<String>,
    #[serde(rename = "dkimResults")]
    dkim_results: Vec<AuthResult>,
    #[serde(rename = "dkimPass")]
    dkim_pass: bool,
    #[serde(rename = "arcResult")]
    arc_result: AuthResult,
    #[serde(rename = "dmarcResult")]
    dmarc_result: AuthResult,
    #[serde(rename = "dmarcPass")]
    dmarc_pass: bool,
    #[serde(rename = "dmarcPolicy")]
    dmarc_policy: DmarcPolicy,
    elapsed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum AuthResult {
    Pass,
    Fail { details: Option<String> },
    SoftFail { details: Option<String> },
    TempError { details: Option<String> },
    PermError { details: Option<String> },
    Neutral { details: Option<String> },
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

async fn dmarc_troubleshoot(
    server: &Server,
    request: DmarcTroubleshootRequest,
) -> Option<DmarcTroubleshootResponse> {
    let remote_ip = request.remote_ip;
    let ehlo_domain = request.ehlo_domain.to_lowercase();
    let mail_from = request.mail_from.to_lowercase();
    let mail_from_domain = mail_from.rsplit_once('@').map(|(_, domain)| domain);

    let local_host = &server.core.network.server_name;

    let now = Instant::now();
    let ehlo_spf_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_spf(
            server
                .inner
                .cache
                .build_auth_parameters(SpfParameters::verify_ehlo(
                    remote_ip,
                    &ehlo_domain,
                    local_host,
                )),
        )
        .await;

    let iprev = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_iprev(server.inner.cache.build_auth_parameters(remote_ip))
        .await;
    let mail_spf_output = if let Some(mail_from_domain) = mail_from_domain {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                mail_from_domain,
                &ehlo_domain,
                local_host,
                &mail_from,
            )))
            .await
    } else {
        server
            .core
            .smtp
            .resolvers
            .dns
            .check_host(server.inner.cache.build_auth_parameters(SpfParameters::new(
                remote_ip,
                &ehlo_domain,
                &ehlo_domain,
                local_host,
                &format!("postmaster@{ehlo_domain}"),
            )))
            .await
    };

    let body = request
        .body
        .unwrap_or_else(|| format!("From: {mail_from}\r\nSubject: test\r\n\r\ntest"));
    let auth_message = AuthenticatedMessage::parse_with_opts(body.as_bytes(), true)?;

    let dkim_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dkim(server.inner.cache.build_auth_parameters(&auth_message))
        .await;
    let dkim_pass = dkim_output
        .iter()
        .any(|d| matches!(d.result(), DkimResult::Pass));

    let arc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_arc(server.inner.cache.build_auth_parameters(&auth_message))
        .await;

    let dmarc_output = server
        .core
        .smtp
        .resolvers
        .dns
        .verify_dmarc(server.inner.cache.build_auth_parameters(DmarcParameters {
            message: &auth_message,
            dkim_output: &dkim_output,
            rfc5321_mail_from_domain: mail_from_domain.unwrap_or(ehlo_domain.as_str()),
            spf_output: &mail_spf_output,
            domain_suffix_fn: |domain| psl::domain_str(domain).unwrap_or(domain),
        }))
        .await;
    let dmarc_pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
        || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
    let dmarc_result = if dmarc_pass {
        DmarcResult::Pass
    } else if dmarc_output.spf_result() != &DmarcResult::None {
        dmarc_output.spf_result().clone()
    } else if dmarc_output.dkim_result() != &DmarcResult::None {
        dmarc_output.dkim_result().clone()
    } else {
        DmarcResult::None
    };

    Some(DmarcTroubleshootResponse {
        spf_ehlo_domain: ehlo_spf_output.domain().to_string(),
        spf_ehlo_result: (&ehlo_spf_output).into(),
        spf_mail_from_domain: mail_spf_output.domain().to_string(),
        spf_mail_from_result: (&mail_spf_output).into(),
        ip_rev_ptr: iprev
            .ptr
            .as_ref()
            .map(|ptr| ptr.as_ref().clone())
            .unwrap_or_default(),
        ip_rev_result: (&iprev).into(),
        dkim_pass,
        dkim_results: dkim_output
            .iter()
            .map(|result| result.result().into())
            .collect(),
        arc_result: arc_output.result().into(),
        dmarc_result: (&dmarc_result).into(),
        dmarc_policy: (&dmarc_output.policy()).into(),
        dmarc_pass,
        elapsed: now.elapsed_ms(),
    })
}

impl From<&SpfOutput> for AuthResult {
    fn from(value: &SpfOutput) -> Self {
        match value.result() {
            SpfResult::Pass => AuthResult::Pass,
            SpfResult::Fail => AuthResult::Fail {
                details: value.explanation().map(|e| e.to_string()),
            },
            SpfResult::SoftFail => AuthResult::SoftFail {
                details: value.explanation().map(|e| e.to_string()),
            },
            SpfResult::Neutral => AuthResult::Neutral {
                details: value.explanation().map(|e| e.to_string()),
            },
            SpfResult::TempError => AuthResult::TempError {
                details: value.explanation().map(|e| e.to_string()),
            },
            SpfResult::PermError => AuthResult::PermError {
                details: value.explanation().map(|e| e.to_string()),
            },
            SpfResult::None => AuthResult::None,
        }
    }
}

impl From<AuthResult> for SpfOutput {
    fn from(value: AuthResult) -> Self {
        match value {
            AuthResult::Pass => SpfOutput::new(String::new()).with_result(SpfResult::Pass),
            AuthResult::Fail { .. } => SpfOutput::new(String::new()).with_result(SpfResult::Fail),
            AuthResult::SoftFail { .. } => {
                SpfOutput::new(String::new()).with_result(SpfResult::SoftFail)
            }
            AuthResult::Neutral { .. } => {
                SpfOutput::new(String::new()).with_result(SpfResult::Neutral)
            }
            AuthResult::TempError { .. } => {
                SpfOutput::new(String::new()).with_result(SpfResult::TempError)
            }
            AuthResult::PermError { .. } => {
                SpfOutput::new(String::new()).with_result(SpfResult::PermError)
            }
            AuthResult::None => SpfOutput::new(String::new()).with_result(SpfResult::None),
        }
    }
}

impl From<&IprevOutput> for AuthResult {
    fn from(value: &IprevOutput) -> Self {
        match &value.result {
            IprevResult::Pass => AuthResult::Pass,
            IprevResult::Fail(error) => AuthResult::Fail {
                details: error.to_string().into(),
            },
            IprevResult::TempError(error) => AuthResult::TempError {
                details: error.to_string().into(),
            },
            IprevResult::PermError(error) => AuthResult::PermError {
                details: error.to_string().into(),
            },
            IprevResult::None => AuthResult::None,
        }
    }
}

impl From<AuthResult> for IprevResult {
    fn from(value: AuthResult) -> Self {
        match value {
            AuthResult::Pass => IprevResult::Pass,
            AuthResult::Fail { details } => {
                IprevResult::Fail(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::TempError { details } => {
                IprevResult::TempError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::PermError { details } => {
                IprevResult::PermError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::None => IprevResult::None,
            _ => IprevResult::None,
        }
    }
}

impl From<&DkimResult> for AuthResult {
    fn from(value: &DkimResult) -> Self {
        match value {
            DkimResult::Pass => AuthResult::Pass,
            DkimResult::Neutral(error) => AuthResult::Neutral {
                details: error.to_string().into(),
            },
            DkimResult::Fail(error) => AuthResult::Fail {
                details: error.to_string().into(),
            },
            DkimResult::PermError(error) => AuthResult::PermError {
                details: error.to_string().into(),
            },
            DkimResult::TempError(error) => AuthResult::TempError {
                details: error.to_string().into(),
            },
            DkimResult::None => AuthResult::None,
        }
    }
}

impl From<AuthResult> for DkimResult {
    fn from(value: AuthResult) -> Self {
        match value {
            AuthResult::Pass => DkimResult::Pass,
            AuthResult::Neutral { details } => {
                DkimResult::Neutral(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::Fail { details } => {
                DkimResult::Fail(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::PermError { details } => {
                DkimResult::PermError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::TempError { details } => {
                DkimResult::TempError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            _ => DkimResult::None,
        }
    }
}

impl From<&DmarcResult> for AuthResult {
    fn from(value: &DmarcResult) -> Self {
        match value {
            DmarcResult::Pass => AuthResult::Pass,
            DmarcResult::Fail(error) => AuthResult::Fail {
                details: error.to_string().into(),
            },
            DmarcResult::TempError(error) => AuthResult::TempError {
                details: error.to_string().into(),
            },
            DmarcResult::PermError(error) => AuthResult::PermError {
                details: error.to_string().into(),
            },
            DmarcResult::None => AuthResult::None,
        }
    }
}

impl From<AuthResult> for DmarcResult {
    fn from(value: AuthResult) -> Self {
        match value {
            AuthResult::Pass => DmarcResult::Pass,
            AuthResult::Fail { details } => {
                DmarcResult::Fail(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::TempError { details } => {
                DmarcResult::TempError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::PermError { details } => {
                DmarcResult::PermError(mail_auth::Error::Io(details.unwrap_or_default()))
            }
            AuthResult::None => DmarcResult::None,
            _ => DmarcResult::None,
        }
    }
}

impl From<&dmarc::Policy> for DmarcPolicy {
    fn from(value: &dmarc::Policy) -> Self {
        match value {
            dmarc::Policy::None => DmarcPolicy::None,
            dmarc::Policy::Quarantine => DmarcPolicy::Quarantine,
            dmarc::Policy::Reject => DmarcPolicy::Reject,
            dmarc::Policy::Unspecified => DmarcPolicy::Unspecified,
        }
    }
}

impl From<DmarcPolicy> for dmarc::Policy {
    fn from(value: DmarcPolicy) -> Self {
        match value {
            DmarcPolicy::None => dmarc::Policy::None,
            DmarcPolicy::Quarantine => dmarc::Policy::Quarantine,
            DmarcPolicy::Reject => dmarc::Policy::Reject,
            DmarcPolicy::Unspecified => dmarc::Policy::Unspecified,
        }
    }
}
