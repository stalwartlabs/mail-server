/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::{config::smtp::report::AggregateFrequency, Core};

use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    dkim::DomainKeyReport,
    dmarc::Dmarc,
    report::DmarcResult,
    spf::Spf,
};
use store::Stores;
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    inbound::{sign::SIGNATURES, TestMessage, TestReportingEvent},
    session::{TestSession, VerifyResponse},
    TempDir, TestSMTP,
};
use smtp::core::{Inner, Session};

const CONFIG: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["jdoe@example.com"]

[session.rcpt]
directory = "'local'"

[session.data.add-headers]
received = true
received-spf = true
auth-results = true
message-id = true
date = true
return-path = false

[report.dkim]
send = "[1, 1s]"
sign = "['rsa']"

[report.spf]
send = "[1, 1s]"
sign = "['rsa']"

[report.dmarc]
send = "[1, 1s]"
sign = "['rsa']"

[report.dmarc.aggregate]
send = "daily"

[auth.spf.verify]
ehlo = [{if = "remote_ip = '10.0.0.2'", then = 'strict'},
        { else = 'relaxed' }]
mail-from = [{if = "remote_ip = '10.0.0.2'", then = 'strict'},
             { else = 'relaxed' }]

[auth.dmarc]
verify = "strict"

[auth.arc]
verify = "strict"

[auth.dkim]
verify = [{if = "sender_domain = 'test.net'", then = 'relaxed'},
         { else = 'strict' }]

"#;

#[tokio::test]
async fn dmarc() {
    let mut inner = Inner::default();
    let tmp_dir = TempDir::new("smtp_dmarc_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG.to_string() + SIGNATURES)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;

    // Create temp dir for queue
    let mut qr = inner.init_test_queue(&core);

    // Add SPF, DKIM and DMARC records
    core.smtp.resolvers.dns.txt_add(
        "mx.example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "example.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all ra=spf-failures rr=e:f:s:n").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "foobar.com",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "ed._domainkey.example.com",
        DomainKey::parse(
            concat!(
                "v=DKIM1; k=ed25519; ",
                "p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "default._domainkey.example.com",
        DomainKey::parse(
            concat!(
                "v=DKIM1; t=s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
                "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt",
                "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v",
                "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi",
                "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB",
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "_report._domainkey.example.com",
        DomainKeyReport::parse(b"ra=dkim-failures; rp=100; rr=d:o:p:s:u:v:x;").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "_dmarc.example.com",
        Dmarc::parse(
            concat!(
                "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo=1;",
                "rua=mailto:dmarc-feedback@example.com;",
                "ruf=mailto:dmarc-failures@example.com"
            )
            .as_bytes(),
        )
        .unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    // Create report channels
    let mut rr = inner.init_test_report();

    // SPF must pass
    let core = build_smtp(core, inner);
    let mut session = Session::test(core.clone());
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session.mail_from("bill@example.com", "550 5.7.23").await;

    // Expect SPF auth failure report
    let message = qr.expect_message().await;
    assert_eq!(
        message.recipients.last().unwrap().address,
        "spf-failures@example.com"
    );
    message
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: spf-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: spf");

    // Second DKIM failure report should be rate limited
    session.mail_from("bill@example.com", "550 5.7.23").await;
    qr.assert_no_events();

    // Invalid DKIM signatures should be rejected
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message(
            "bill@example.com",
            &["jdoe@example.com"],
            "test:invalid_dkim",
            "550 5.7.20",
        )
        .await;

    // Expect DKIM auth failure report
    let message = qr.expect_message().await;
    assert_eq!(
        message.recipients.last().unwrap().address,
        "dkim-failures@example.com"
    );
    message
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: dkim-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: bodyhash");

    // Second DKIM failure report should be rate limited
    session
        .send_message(
            "bill@example.com",
            &["jdoe@example.com"],
            "test:invalid_dkim",
            "550 5.7.20",
        )
        .await;
    qr.assert_no_events();

    // Invalid ARC should be rejected
    session
        .send_message(
            "bill@example.com",
            &["jdoe@example.com"],
            "test:invalid_arc",
            "550 5.7.29",
        )
        .await;
    qr.assert_no_events();

    // Unaligned DMARC should be rejected
    core.core.smtp.resolvers.dns.txt_add(
        "test.net",
        Spf::parse(b"v=spf1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    session
        .send_message(
            "joe@test.net",
            &["jdoe@example.com"],
            "test:invalid_dkim",
            "550 5.7.1",
        )
        .await;

    // Expect DMARC auth failure report
    let message = qr.expect_message().await;
    assert_eq!(
        message.recipients.last().unwrap().address,
        "dmarc-failures@example.com"
    );
    message
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: dmarc-failures@example.com")
        .assert_contains("Feedback-Type: auth-failure")
        .assert_contains("Auth-Failure: dmarc")
        .assert_contains("dmarc=3Dnone");

    // Expect DMARC aggregate report
    let report = rr.read_report().await.unwrap_dmarc();
    assert_eq!(report.domain, "example.com");
    assert_eq!(report.interval, AggregateFrequency::Daily);
    assert_eq!(report.dmarc_record.rua().len(), 1);
    assert_eq!(report.report_record.dmarc_spf_result(), DmarcResult::Fail);

    // Second DMARC failure report should be rate limited
    session
        .send_message(
            "joe@test.net",
            &["jdoe@example.com"],
            "test:invalid_dkim",
            "550 5.7.1",
        )
        .await;
    qr.assert_no_events();

    // Messagess passing DMARC should be accepted
    session
        .send_message(
            "bill@example.com",
            &["jdoe@example.com"],
            "test:dkim",
            "250",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("dkim=pass")
        .assert_contains("spf=pass")
        .assert_contains("dmarc=pass")
        .assert_contains("Received-SPF: pass");
}
