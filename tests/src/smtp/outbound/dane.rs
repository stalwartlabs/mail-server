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
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    num::ParseIntError,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
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
use utils::config::{if_block::IfBlock, ServerProtocol};

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    TestConfig, TestSMTP,
};
use smtp::{
    config::{AggregateFrequency, RequireOptional},
    core::{Resolvers, Session, SMTP},
    outbound::dane::{DnssecResolver, Tlsa, TlsaEntry},
    queue::{Error, ErrorDetails, Status},
    reporting::PolicyType,
};

#[tokio::test]
#[serial_test::serial]
async fn dane_verify() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_dane_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    // Fail on missing TLSA record
    let mut local_qr = core.init_test_queue("smtp_dane_local");
    let mut rr = core.init_test_report();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.queue.config.tls.dane = IfBlock::new(RequireOptional::Require);
    core.report.config.tls.send = IfBlock::new(AggregateFrequency::Weekly);

    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local_qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local_qr
        .expect_message()
        .await
        .read_lines(&local_qr)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA records found");
    local_qr.read_event().await.assert_reload();
    local_qr.assert_no_events();

    // Expect TLS failure report
    let report = rr.read_report().await.unwrap_tls();
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
    core.resolvers.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local_qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local_qr
        .expect_message()
        .await
        .read_lines(&local_qr)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching certificates found");
    local_qr.read_event().await.assert_reload();
    local_qr.assert_no_events();

    // Expect TLS failure report
    let report = rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote_qr.assert_no_events();

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
    core.resolvers.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local_qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local_qr.read_event().await.assert_reload();
    local_qr.assert_no_events();
    remote_qr
        .expect_message()
        .await
        .read_lines(&remote_qr)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());
}

#[tokio::test]
async fn dane_test() {
    let conf = ResolverConfig::cloudflare_tls();
    let mut opts = ResolverOpts::default();
    opts.validate = true;
    opts.try_tcp_on_error = true;

    let r = Resolvers {
        dns: Resolver::new_cloudflare().unwrap(),
        dnssec: DnssecResolver {
            resolver: AsyncResolver::tokio(conf, opts),
        },
        cache: smtp::core::DnsCache {
            tlsa: LruCache::with_capacity(10),
            mta_sts: LruCache::with_capacity(10),
        },
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

        assert_eq!(
            tlsa.verify(&tracing::info_span!("test_span"), &host, Some(&certs)),
            Ok(())
        );

        // Failed DANE verification
        certs.remove(0);
        assert_eq!(
            tlsa.verify(&tracing::info_span!("test_span"), &host, Some(&certs)),
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
