/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    num::ParseIntError,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    config::{
        server::ServerProtocol,
        smtp::resolver::{DnsRecordCache, DnssecResolver, Resolvers, Tlsa, TlsaEntry},
    },
    Core,
};
use mail_auth::{
    common::{
        lru::{DnsCache, LruCache},
        parse::TxtRecordParser,
    },
    hickory_resolver::{
        config::{ResolverConfig, ResolverOpts},
        AsyncResolver,
    },
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
    Resolver, MX,
};
use rustls_pki_types::CertificateDer;
use utils::suffixlist::PublicSuffix;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
    outbound::TestServer,
    session::{TestSession, VerifyResponse},
};
use smtp::outbound::dane::verify::TlsaVerify;
use smtp::{
    core::SMTP,
    queue::{Error, ErrorDetails, Status},
    reporting::PolicyType,
};

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[report.tls.aggregate]
send = "weekly"

[queue.outbound.tls]
dane = "require"
starttls = "require"

"#;

const REMOTE: &str = "
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.data.add-headers]
received = true
received-spf = true
auth-results = true
message-id = true
date = true
return-path = false

";

#[tokio::test]
#[serial_test::serial]
async fn dane_verify() {
    // Enable logging
    crate::enable_logging();


    // Start test server
    let mut remote = TestServer::new("smtp_dane_remote", REMOTE, true).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    // Fail on missing TLSA record
    let mut local = TestServer::new("smtp_dane_local", LOCAL, true).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.core.smtp.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local
        .qr
        .expect_message()
        .await
        .read_lines(&local.qr)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA records found");
    local.qr.read_event().await.assert_reload();
    local.qr.assert_no_events();

    // Expect TLS failure report
    let report = local.rr.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // DANE failure with no matching certificates
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_sha256: true,
            is_spki: true,
            data: vec![1, 2, 3],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    core.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local
        .qr
        .expect_message()
        .await
        .read_lines(&local.qr)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching certificates found");
    local.qr.read_event().await.assert_reload();
    local.qr.assert_no_events();

    // Expect TLS failure report
    let report = local.rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.qr.assert_no_events();

    // DANE successful delivery
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_sha256: true,
            is_spki: true,
            data: vec![
                73, 186, 44, 106, 13, 198, 100, 180, 0, 44, 158, 188, 15, 195, 39, 198, 61, 254,
                215, 237, 100, 26, 15, 155, 219, 235, 120, 64, 128, 172, 17, 0,
            ],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    core.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local.qr.read_event().await.assert_reload();
    local.qr.assert_no_events();
    remote
        .qr
        .expect_message()
        .await
        .read_lines(&remote.qr)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());
}

#[tokio::test]
async fn dane_test() {
    let conf = ResolverConfig::cloudflare_tls();
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    opts.try_tcp_on_error = true;

    let mut core = Core::default();
    core.smtp.resolvers = Resolvers {
        dns: Resolver::new_cloudflare().unwrap(),
        dnssec: DnssecResolver {
            resolver: AsyncResolver::tokio(conf, opts),
        },
        cache: DnsRecordCache {
            tlsa: LruCache::with_capacity(10),
            mta_sts: LruCache::with_capacity(10),
        },
        psl: PublicSuffix::default(),
    };
    let r = SMTP {
        core: core.into(),
        inner: Default::default(),
    };

    // Add dns entries
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dane");
    let mut file = path.clone();
    file.push("dns.txt");

    let mut hosts = BTreeSet::new();
    let mut tlsa = Tlsa {
        entries: Vec::new(),
        has_end_entities: false,
        has_intermediates: false,
    };
    let mut hostname = String::new();

    for line in BufReader::new(File::open(file).unwrap()).lines() {
        let line = line.unwrap();
        let mut is_end_entity = false;
        for (pos, item) in line.split_whitespace().enumerate() {
            match pos {
                0 => {
                    if hostname != item && !hostname.is_empty() {
                        r.tlsa_add(hostname, tlsa, Instant::now() + Duration::from_secs(30));
                        tlsa = Tlsa {
                            entries: Vec::new(),
                            has_end_entities: false,
                            has_intermediates: false,
                        };
                    }
                    hosts.insert(item.strip_prefix("_25._tcp.").unwrap().to_string());
                    hostname = item.to_string();
                }
                1 => {
                    is_end_entity = item == "3";
                }
                4 => {
                    if is_end_entity {
                        tlsa.has_end_entities = true;
                    } else {
                        tlsa.has_intermediates = true;
                    }
                    tlsa.entries.push(TlsaEntry {
                        is_end_entity,
                        is_sha256: true,
                        is_spki: true,
                        data: decode_hex(item).unwrap(),
                    });
                }
                _ => (),
            }
        }
    }
    r.tlsa_add(hostname, tlsa, Instant::now() + Duration::from_secs(30));

    // Add certificates
    assert!(!hosts.is_empty());
    for host in hosts {
        // Add certificates
        let mut certs = Vec::new();
        for num in 0..6 {
            let mut file = path.clone();
            file.push(format!("{host}.{num}.cert"));
            if file.exists() {
                certs.push(CertificateDer::from(fs::read(file).unwrap()));
            } else {
                break;
            }
        }

        // Successful DANE verification
        let tlsa = r
            .tlsa_lookup(format!("_25._tcp.{host}."))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(tlsa.verify(0, &host, Some(&certs)), Ok(()));

        // Failed DANE verification
        certs.remove(0);
        assert_eq!(
            tlsa.verify(0, &host, Some(&certs)),
            Err(Status::PermanentFailure(Error::DaneError(ErrorDetails {
                entity: host.to_string(),
                details: "No matching certificates found in TLSA records".to_string()
            })))
        );
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
