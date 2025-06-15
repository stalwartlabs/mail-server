/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::config::server::ServerProtocol;
use mail_auth::MX;
use store::write::now;

use crate::smtp::{
    DnsCache, TestSMTP,
    inbound::TestMessage,
    session::{TestSession, VerifyResponse},
};

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[queue.outbound]
hostname = "'badtls.foobar.org'"

[queue.outbound.tls]
starttls = [ { if = "retry_num > 0 && last_error == 'tls'", then = "disable"},
             { else = "optional" }]
"#;

const REMOTE: &str = r#"
[session.rcpt]
relay = true

[session.ehlo]
reject-non-fqdn = false

[session.extensions]
dsn = true
chunking = false
"#;

#[tokio::test]
#[serial_test::serial]
async fn starttls_optional() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let mut remote = TestSMTP::new("smtp_starttls_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    // Retry on failed STARTTLS
    let mut local = TestSMTP::new("smtp_starttls_local", LOCAL).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone());
    let mut retry = local.queue_receiver.expect_message().await;
    let prev_due = retry.domains[0].retry.due;
    let next_due = now();
    let queue_id = retry.queue_id;
    retry.domains[0].retry.due = next_due;
    retry
        .save_changes(&core, prev_due.into(), next_due.into())
        .await;
    local
        .queue_receiver
        .delivery_attempt(queue_id)
        .await
        .try_deliver(core.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    remote
        .queue_receiver
        .expect_message()
        .await
        .read_lines(&remote.queue_receiver)
        .await
        .assert_not_contains("using TLSv1.3 with cipher");
}
