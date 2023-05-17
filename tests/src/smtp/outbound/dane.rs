/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{
    common::parse::TxtRecordParser,
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
    MX,
};
use utils::config::ServerProtocol;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    TestConfig, TestSMTP,
};
use smtp::{
    config::{AggregateFrequency, IfBlock, RequireOptional},
    core::{Session, SMTP},
    outbound::dane::{Tlsa, TlsaEntry},
    queue::{manager::Queue, DeliveryAttempt},
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
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA records found");
    local_qr.read_event().await.unwrap_done();

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
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching certificates found");
    local_qr.read_event().await.unwrap_done();

    // Expect TLS failure report
    let report = rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote_qr.assert_empty_queue();

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
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr.read_event().await.unwrap_done();
    remote_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = rr.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());
}
