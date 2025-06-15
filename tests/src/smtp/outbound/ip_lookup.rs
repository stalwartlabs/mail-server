/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::config::server::ServerProtocol;
use mail_auth::{IpLookupStrategy, MX};

use crate::smtp::{DnsCache, TestSMTP, session::TestSession};

const LOCAL: &str = r#"
[session.rcpt]
relay = true

[queue.outbound]
ip-strategy = "ipv6_then_ipv4"
"#;

const REMOTE: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true
"#;

#[tokio::test]
#[serial_test::serial]
async fn ip_lookup_strategy() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let mut remote = TestSMTP::new("smtp_iplookup_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;

    for strategy in [IpLookupStrategy::Ipv6Only, IpLookupStrategy::Ipv6thenIpv4] {
        //println!("-> Strategy: {:?}", strategy);
        // Add mock DNS entries
        let mut local = TestSMTP::new("smtp_iplookup_local", LOCAL).await;
        let core = local.build_smtp();
        core.mx_add(
            "foobar.org",
            vec![MX {
                exchanges: vec!["mx.foobar.org".to_string()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(10),
        );
        if matches!(strategy, IpLookupStrategy::Ipv6thenIpv4) {
            core.ipv4_add(
                "mx.foobar.org",
                vec!["127.0.0.1".parse().unwrap()],
                Instant::now() + Duration::from_secs(10),
            );
        }
        core.ipv6_add(
            "mx.foobar.org",
            vec!["::1".parse().unwrap()],
            Instant::now() + Duration::from_secs(10),
        );

        // Retry on failed STARTTLS
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        if matches!(strategy, IpLookupStrategy::Ipv6thenIpv4) {
            remote.queue_receiver.expect_message().await;
        } else {
            let message = local.queue_receiver.last_queued_message().await;
            let status = message.domains[0].status.to_string();
            assert!(
                status.contains("Connection refused"),
                "Message: {:?}",
                message
            );
        }
    }
}
