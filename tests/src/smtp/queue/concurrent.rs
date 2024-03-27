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

use std::time::{Duration, Instant};

use common::config::server::ServerProtocol;
use mail_auth::MX;

use crate::smtp::{outbound::TestServer, session::TestSession};
use smtp::queue::manager::Queue;

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[session.data.limits]
messages = 200

"#;

const REMOTE: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

"#;

#[tokio::test]
#[serial_test::serial]
async fn concurrent_queue() {
    /*let disable = true;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let remote = TestServer::new("smtp_concurrent_queue_remote", REMOTE, true).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    let local = TestServer::new("smtp_concurrent_queue_local", LOCAL, true).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.core.smtp.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(100),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(100),
    );

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    // Send 100 test messages
    for _ in 0..100 {
        session
            .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
            .await;
    }

    // Spawn 20 concurrent queues at different times
    for _ in 0..10 {
        let local = local.instance.clone();
        tokio::spawn(async move {
            Queue::new(local).process_events().await;
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..10 {
        let local = local.instance.clone();
        tokio::spawn(async move {
            Queue::new(local).process_events().await;
        });
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    local.qr.assert_queue_is_empty().await;
    let remote_messages = remote.qr.read_queued_messages().await;
    assert_eq!(remote_messages.len(), 100);

    // Make sure local store is queue
    core.core
        .storage
        .data
        .assert_is_empty(core.core.storage.blob.clone())
        .await;
}
