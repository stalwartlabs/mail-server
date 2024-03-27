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
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use mail_auth::MX;
use store::write::now;

use crate::smtp::{
    inbound::TestQueueEvent, outbound::TestServer, queue::manager::new_message,
    session::TestSession,
};
use smtp::queue::{Message, QueueEnvelope};

const CONFIG: &str = r#"
[session.rcpt]
relay = true

[queue.schedule]
retry = "1h"
notify = "1h"
expire = "1h"

[[queue.throttle]]
match = "sender_domain = 'foobar.org'"
key = 'sender_domain'
concurrency = 1
enable = true

[[queue.throttle]]
match = "sender_domain = 'foobar.net'"
key = 'sender_domain'
rate = '1/30m'
enable = true

[[queue.throttle]]
match = "rcpt_domain = 'example.org'"
key = 'rcpt_domain'
concurrency = 1
enable = true

[[queue.throttle]]
match = "rcpt_domain = 'example.net'"
key = 'rcpt_domain'
rate = '1/40m'
enable = true

[[queue.throttle]]
match = "mx = 'mx.test.org'"
key = 'mx'
concurrency = 1
enable = true

[[queue.throttle]]
match = "mx = 'mx.test.net'"
key = 'mx'
rate = '1/50m'
enable = true
"#;

#[tokio::test]
async fn throttle_outbound() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Build test message
    let mut test_message = new_message(0);
    test_message.return_path_domain = "foobar.org".to_string();

    let mut local = TestServer::new("smtp_throttle_outbound", CONFIG, true).await;

    let core = local.build_smtp();
    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@foobar.org", &["bill@test.org"], "test:no_dkim", "250")
        .await;
    assert_eq!(local.qr.last_queued_due().await as i64 - now() as i64, 0);

    // Throttle sender
    let span = tracing::info_span!("test");
    let mut in_flight = vec![];
    let throttle = &core.core.smtp.queue.throttle;
    for t in &throttle.sender {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "", ""),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(!in_flight.is_empty());

    // Expect concurrency throttle for sender domain 'foobar.org'
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.qr.read_event().await.unwrap_on_hold();
    in_flight.clear();

    // Expect rate limit throttle for sender domain 'foobar.net'
    test_message.return_path_domain = "foobar.net".to_string();
    for t in &throttle.sender {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "", ""),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(in_flight.is_empty());
    session
        .send_message("john@foobar.net", &["bill@test.org"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.qr.read_event().await.assert_reload();
    let due = local.qr.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);

    // Expect concurrency throttle for recipient domain 'example.org'
    test_message.return_path_domain = "test.net".to_string();
    for t in &throttle.rcpt {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "example.org", ""),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(!in_flight.is_empty());
    session
        .send_message(
            "john@test.net",
            &["jane@example.org"],
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
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.qr.read_event().await.unwrap_on_hold();
    in_flight.clear();

    // Expect rate limit throttle for recipient domain 'example.org'
    for t in &throttle.rcpt {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "example.net", ""),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(in_flight.is_empty());
    session
        .send_message(
            "john@test.net",
            &["jane@example.net"],
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
    tokio::time::sleep(Duration::from_millis(100)).await;
    local.qr.read_event().await.assert_reload();
    let due = local.qr.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);

    // Expect concurrency throttle for mx 'mx.test.org'
    core.core.smtp.resolvers.dns.mx_add(
        "test.org",
        vec![MX {
            exchanges: vec!["mx.test.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.test.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    for t in &throttle.host {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "test.org", "mx.test.org"),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(!in_flight.is_empty());
    session
        .send_message("john@test.net", &["jane@test.org"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    local.qr.read_event().await.unwrap_on_hold();
    in_flight.clear();

    // Expect rate limit throttle for mx 'mx.test.net'
    core.core.smtp.resolvers.dns.mx_add(
        "test.net",
        vec![MX {
            exchanges: vec!["mx.test.net".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.test.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    for t in &throttle.host {
        core.is_allowed(
            t,
            &QueueEnvelope::test(&test_message, "example.net", "mx.test.net"),
            &mut in_flight,
            &span,
        )
        .await
        .unwrap();
    }
    assert!(in_flight.is_empty());
    session
        .send_message("john@test.net", &["jane@test.net"], "test:no_dkim", "250")
        .await;
    local
        .qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    local.qr.read_event().await.assert_reload();
    let due = local.qr.last_queued_due().await - now();
    assert!(due > 0, "Due: {}", due);
}

pub trait TestQueueEnvelope<'x> {
    fn test(message: &'x Message, domain: &'x str, mx: &'x str) -> Self;
}

impl<'x> TestQueueEnvelope<'x> for QueueEnvelope<'x> {
    fn test(message: &'x Message, domain: &'x str, mx: &'x str) -> Self {
        QueueEnvelope {
            message,
            domain,
            mx,
            remote_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            local_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}
