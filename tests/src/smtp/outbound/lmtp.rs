/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use crate::smtp::{
    inbound::TestMessage,
    outbound::TestServer,
    session::{TestSession, VerifyResponse},
};
use common::config::server::ServerProtocol;
use smtp::queue::{DeliveryAttempt, Event};
use store::write::now;

const REMOTE: &str = "
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.extensions]
dsn = true
";

const LOCAL: &str = r#"
[queue.outbound]
next-hop = [{if = "rcpt_domain = 'foobar.org'", then = "'lmtp'"},
            {else = false}]

[session.rcpt]
relay = true
max-recipients = 100

[session.extensions]
dsn = true

[queue.schedule]
retry = "1s"
notify = [{if = "rcpt_domain = 'foobar.org'", then = "[1s, 2s]"},
          {else = [1s]}]
expire = [{if = "rcpt_domain = 'foobar.org'", then = "4s"},
          {else = "5s"}]

[queue.outbound.timeouts]
data = "50ms"

[remote.lmtp]
address = lmtp.foobar.org
port = 9924
protocol = 'lmtp'
concurrency = 5

[remote.lmtp.tls]
implicit = true
allow-invalid-certs = true
"#;

#[tokio::test]
#[serial_test::serial]
async fn lmtp_delivery() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut remote = TestServer::new("lmtp_delivery_remote", REMOTE, true).await;
    let _rx = remote.start(&[ServerProtocol::Lmtp]).await;

    // Multiple delivery attempts
    let mut local = TestServer::new("lmtp_delivery_local", LOCAL, true).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.core.smtp.resolvers.dns.ipv4_add(
        "lmtp.foobar.org",
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
            &[
                "<bill@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<jane@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<john@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
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
    let mut dsn = Vec::new();
    loop {
        match local.qr.try_read_event().await {
            Some(Event::Reload) => {}
            Some(Event::OnHold(_)) => unreachable!(),
            None | Some(Event::Stop) => break,
        }

        let events = core.next_event().await;
        if events.is_empty() {
            break;
        }
        let now = now();
        for event in events {
            if event.due > now {
                tokio::time::sleep(Duration::from_secs(event.due - now)).await;
            }

            let message = core.read_message(event.queue_id).await.unwrap();
            if message.return_path.is_empty() {
                message.clone().remove(&core, event.due).await;
                dsn.push(message);
            } else {
                DeliveryAttempt::new(event).try_deliver(core.clone()).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    local.qr.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 4);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local.qr)
        .await
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("<jane@foobar.org> (delivered to")
        .assert_contains("<john@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.org> (host 'lmtp.foobar.org' rejected command");

    dsn.next()
        .unwrap()
        .read_lines(&local.qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: failed");

    assert_eq!(
        remote
            .qr
            .expect_message()
            .await
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec![
            "bill@foobar.org".to_string(),
            "jane@foobar.org".to_string(),
            "john@foobar.org".to_string()
        ]
    );
    remote.qr.assert_no_events();
}
