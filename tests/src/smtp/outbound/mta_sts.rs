/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    config::{server::ServerProtocol, smtp::resolver::Policy},
    ipc::PolicyType,
};
use mail_auth::{
    common::parse::TxtRecordParser,
    mta_sts::{MtaSts, ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
    MX,
};

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
    session::{TestSession, VerifyResponse},
    TestSMTP,
};
use smtp::outbound::mta_sts::{lookup::STS_TEST_POLICY, parse::ParsePolicy};

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[queue.outbound.tls]
mta-sts = "require"

[report.tls.aggregate]
send = "weekly"

"#;

const REMOTE: &str = r#"
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

"#;

#[tokio::test]
#[serial_test::serial]
async fn mta_sts_verify() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let mut remote = TestSMTP::new("smtp_mta_sts_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    // Fail on missing MTA-STS record
    let mut local = TestSMTP::new("smtp_mta_sts_local", LOCAL).await;

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
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local
        .queue_receiver
        .expect_message()
        .await
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("Record not found");
    local.queue_receiver.read_event().await.assert_reload();

    // Expect TLS failure report
    let report = local.report_receiver.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Sts(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::Other
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // MTA-STS policy fetch failure
    core.core.smtp.resolvers.dns.txt_add(
        "_mta-sts.foobar.org",
        MtaSts::parse(b"v=STSv1; id=policy_will_fail;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local
        .queue_receiver
        .expect_message()
        .await
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("No 'mx' entries found");
    local.queue_receiver.read_event().await.assert_reload();

    // Expect TLS failure report
    let report = local.report_receiver.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Sts(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::StsPolicyInvalid
    );

    // MTA-STS policy does not authorize mx.foobar.org
    let policy = concat!(
        "version: STSv1\n",
        "mode: enforce\n",
        "mx: mail.foobar.net\n",
        "max_age: 604800\n"
    );
    STS_TEST_POLICY.lock().extend_from_slice(policy.as_bytes());
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local
        .queue_receiver
        .expect_message()
        .await
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<bill@foobar.org> (MTA-STS failed to authenticate")
        .assert_contains("not authorized by policy");
    local.queue_receiver.read_event().await.assert_reload();

    // Expect TLS failure report
    let report = local.report_receiver.read_report().await.unwrap_tls();
    assert_eq!(
        report.policy,
        PolicyType::Sts(
            Arc::new(Policy::parse(policy, "policy_will_fail".to_string()).unwrap()).into()
        )
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.queue_receiver.assert_no_events();

    // MTA-STS successful validation
    core.core.smtp.resolvers.dns.txt_add(
        "_mta-sts.foobar.org",
        MtaSts::parse(b"v=STSv1; id=policy_will_work;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );
    let policy = concat!(
        "version: STSv1\n",
        "mode: enforce\n",
        "mx: *.foobar.org\n",
        "max_age: 604800\n"
    );
    STS_TEST_POLICY.lock().clear();
    STS_TEST_POLICY.lock().extend_from_slice(policy.as_bytes());
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local.queue_receiver.read_event().await.assert_reload();
    remote
        .queue_receiver
        .expect_message()
        .await
        .read_lines(&remote.queue_receiver)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.report_receiver.read_report().await.unwrap_tls();
    assert_eq!(
        report.policy,
        PolicyType::Sts(
            Arc::new(Policy::parse(policy, "policy_will_work".to_string()).unwrap()).into()
        )
    );
    assert!(report.failure.is_none());
}
