/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::{config::server::ServerProtocol, core::BuildServer, ipc::QueueEvent};
use mail_auth::MX;

use crate::smtp::{DnsCache, TestSMTP, session::TestSession};
use smtp::queue::manager::Queue;

const LOCAL: &str = r#"
[spam-filter]
enable = false

[session.rcpt]
relay = true

[session.data.limits]
messages = 2000

[queue.threads]
remote = 4

[queue.schedule]
retry = "1s"
notify = "1d"
expire = "1d"
"#;

const REMOTE: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[spam-filter]
enable = false

"#;

const NUM_MESSAGES: usize = 100;
const NUM_QUEUES: usize = 10;

#[tokio::test(flavor = "multi_thread", worker_threads = 18)]
#[serial_test::serial]
async fn concurrent_queue() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let remote = TestSMTP::new("smtp_concurrent_queue_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    let local = TestSMTP::with_database("smtp_concurrent_queue_local", LOCAL, "mysql").await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(100),
    );
    core.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(100),
    );

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    // Spawn concurrent queues
    let mut inners = vec![];
    for _ in 0..NUM_QUEUES {
        let (inner, rxs) = local.inner_with_rxs();
        let server = inner.build_server();
        server.mx_add(
            "foobar.org",
            vec![MX {
                exchanges: vec!["mx.foobar.org".to_string()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(100),
        );
        server.ipv4_add(
            "mx.foobar.org",
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(100),
        );
        inners.push(inner.clone());
        tokio::spawn(async move {
            Queue::new(inner, rxs.queue_rx.unwrap()).start().await;
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send 1000 test messages
    for _ in 0..(NUM_MESSAGES / 2) {
        session
            .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
            .await;
    }

    // Wake up all queues
    for inner in &inners {
        inner.ipc.queue_tx.send(QueueEvent::Refresh).await.unwrap();
    }
    for _ in 0..(NUM_MESSAGES / 2) {
        session
            .send_message(
                "john@test.org",
                &["delay-random@foobar.org"],
                "test:no_dkim",
                "250",
            )
            .await;
    }

    loop {
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let m = local.queue_receiver.read_queued_messages().await.len();
        let e = local.queue_receiver.read_queued_events().await.len();

        if m + e != 0 {
            println!("Queue still has {} messages and {} events", m, e);
            /*for inner in &inners {
                inner
                    .ipc
                    .queue_tx
                    .send(QueueEvent::Refresh)
                    .await
                    .unwrap();
            }*/
        } else {
            break;
        }
    }

    local.queue_receiver.assert_queue_is_empty().await;
    let remote_messages = remote.queue_receiver.read_queued_messages().await;
    assert_eq!(remote_messages.len(), NUM_MESSAGES);

    // Make sure local store is queue
    core.core
        .storage
        .data
        .assert_is_empty(core.core.storage.blob.clone())
        .await;
}
