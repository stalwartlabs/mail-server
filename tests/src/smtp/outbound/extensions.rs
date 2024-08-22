/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::config::server::ServerProtocol;
use mail_auth::MX;
use smtp_proto::{MAIL_REQUIRETLS, MAIL_RET_HDRS, MAIL_SMTPUTF8, RCPT_NOTIFY_NEVER};

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::TestServer,
    session::{TestSession, VerifyResponse},
};

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[session.extensions]
dsn = true
"#;

const REMOTE: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.data.limits]
size = 1500

[session.extensions]
dsn = true
requiretls = true

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
async fn extensions() {
    // Enable logging
    crate::enable_logging();


    // Start test server
    let mut remote = TestServer::new("smtp_ext_remote", REMOTE, true).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    // Successful delivery with DSN
    let mut local = TestServer::new("smtp_ext_local", LOCAL, true).await;

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

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &["<bill@foobar.org> NOTIFY=SUCCESS,FAILURE"],
            "test:no_dkim",
            "250",
        )
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
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: delivered");
    local.qr.read_event().await.assert_reload();
    remote
        .qr
        .expect_message()
        .await
        .read_lines(&remote.qr)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Test SIZE extension
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:arc", "250")
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
        .assert_contains("<bill@foobar.org> (host 'mx.foobar.org' rejected command 'MAIL FROM:")
        .assert_contains("Action: failed")
        .assert_contains("Diagnostic-Code: smtp;552")
        .assert_contains("Status: 5.3.4");
    local.qr.read_event().await.assert_reload();
    remote.qr.assert_no_events();

    // Test DSN, SMTPUTF8 and REQUIRETLS extensions
    session
        .send_message(
            "<john@test.org> ENVID=abc123 RET=HDRS REQUIRETLS SMTPUTF8",
            &["<bill@foobar.org> NOTIFY=NEVER"],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local.qr.read_event().await.assert_reload();
    let message = remote.qr.expect_message().await;
    assert_eq!(message.env_id, Some("abc123".to_string()));
    assert!((message.flags & MAIL_RET_HDRS) != 0);
    assert!((message.flags & MAIL_REQUIRETLS) != 0);
    assert!((message.flags & MAIL_SMTPUTF8) != 0);
    assert!((message.recipients.last().unwrap().flags & RCPT_NOTIFY_NEVER) != 0);
}
