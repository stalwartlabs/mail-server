/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::TestServer,
    session::{TestSession, VerifyResponse},
};
use smtp::queue::{DeliveryAttempt, Event};
use store::write::now;

const CONFIG: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.extensions]
deliver-by = "1h"
future-release = "1h"

[queue.schedule]
retry = "[1s, 2s, 3s]"
notify = [{if = "sender_domain = 'test.org'", then = "[1s, 2s]"},
           {else = ['15h', '22h']}]
expire = [{if = "sender_domain = 'test.org'", then = "6s"},
          {else = '1d'}]
"#;

#[tokio::test]
async fn queue_retry() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Create temp dir for queue
    let mut local = TestServer::new("smtp_queue_retry_test", CONFIG, true).await;

    // Create test message
    let core = local.build_smtp();
    let mut session = local.new_session();
    let qr = &mut local.qr;

    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    let attempt = qr.expect_message_then_deliver().await;

    // Expect a failed DSN
    attempt.try_deliver(core.clone()).await;
    let message = qr.expect_message().await;
    assert_eq!(message.return_path, "");
    assert_eq!(message.domains.first().unwrap().domain, "test.org");
    assert_eq!(message.recipients.first().unwrap().address, "john@test.org");
    message
        .read_lines(qr)
        .await
        .assert_contains("Content-Type: multipart/report")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");
    qr.read_event().await.assert_reload();
    qr.clear_queue(&core).await;

    // Expect a failed DSN for foobar.org, followed by two delayed DSN and
    // a final failed DSN for _dns_error.org.
    session
        .send_message(
            "john@test.org",
            &["bill@foobar.org", "jane@_dns_error.org"],
            "test:no_dkim",
            "250",
        )
        .await;
    let attempt = qr.expect_message_then_deliver().await;
    let mut dsn = Vec::new();
    let mut retries = Vec::new();
    attempt.try_deliver(core.clone()).await;
    loop {
        match qr.try_read_event().await {
            Some(Event::Reload) => {}
            Some(Event::OnHold(_)) => unreachable!(),
            None | Some(Event::Stop) => break,
        }

        let now = now();
        let events = core.next_event().await;
        if events.is_empty() {
            break;
        }
        for event in events {
            if event.due > now {
                tokio::time::sleep(Duration::from_secs(event.due - now)).await;
            }

            let message = core.read_message(event.queue_id).await.unwrap();
            if message.return_path.is_empty() {
                message.clone().remove(&core, event.due).await;
                dsn.push(message);
            } else {
                retries.push(event.due - now);
                DeliveryAttempt::new(event).try_deliver(core.clone()).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    qr.assert_queue_is_empty().await;
    assert_eq!(retries, vec![1, 2, 3]);
    assert_eq!(dsn.len(), 4);
    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<bill@foobar.org> (failed to lookup 'foobar.org'")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: failed");

    // Test FUTURERELEASE + DELIVERBY (RETURN)
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.eval_session_params().await;
    session
        .send_message(
            "<bill@foobar.org> HOLDFOR=60 BY=3600;R",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let now_ = now();
    let message = qr.expect_message().await;
    assert!([59, 60].contains(&(qr.message_due(message.id).await - now_)));
    assert!([59, 60].contains(&(message.next_delivery_event() - now_)));
    assert!([3599, 3600].contains(&(message.domains.first().unwrap().expires - now_)));
    assert!([54059, 54060].contains(&(message.domains.first().unwrap().notify.due - now_)));

    // Test DELIVERBY (NOTIFY)
    session
        .send_message(
            "<bill@foobar.org> BY=3600;N",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let schedule = qr.expect_message().await;
    assert!([3599, 3600].contains(&(schedule.domains.first().unwrap().notify.due - now())));
}
