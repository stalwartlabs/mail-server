/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::config::server::ServerProtocol;
use mail_auth::MX;
use store::write::now;

use crate::smtp::{outbound::TestServer, session::TestSession};

const LOCAL: &str = r#"
[queue.outbound]
next-hop = [{if = "retry_num > 0", then = "'fallback'"},
            {else = false}]

[session.rcpt]
relay = true
max-recipients = 100

[session.extensions]
dsn = true

[remote.fallback]
address = fallback.foobar.org
port = 9925
protocol = 'smtp'
concurrency = 5

[remote.fallback.tls]
implicit = false
allow-invalid-certs = true

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
async fn fallback_relay() {
    /*let disable = 1;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut remote = TestServer::new("smtp_fallback_remote", REMOTE, true).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;
    let mut local = TestServer::new("smtp_fallback_local", LOCAL, true).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.core.smtp.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["_dns_error.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    /*core.core.smtp.resolvers.dns.ipv4_add(
        "unreachable.foobar.org",
        vec!["127.0.0.2".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );*/
    core.core.smtp.resolvers.dns.ipv4_add(
        "fallback.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
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
    let mut retry = local.qr.expect_message().await;
    let prev_due = retry.domains[0].retry.due;
    let next_due = now();
    let queue_id = retry.id;
    retry.domains[0].retry.due = next_due;
    retry
        .save_changes(&core, prev_due.into(), next_due.into())
        .await;
    local
        .qr
        .delivery_attempt(queue_id)
        .await
        .try_deliver(core.clone())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    remote.qr.expect_message().await;
}
