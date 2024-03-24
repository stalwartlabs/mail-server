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
    sync::Arc,
    time::{Duration, Instant},
};

use crate::smtp::{
    inbound::TestMessage,
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use common::{config::server::ServerProtocol, expr::if_block::IfBlock};
use smtp::{
    core::{Session, SMTP},
    queue::{DeliveryAttempt, Event},
};
use store::write::now;
use utils::config::Config;

const REMOTE: &str = "
[remote.lmtp]
address = lmtp.foobar.org
port = 9924
protocol = 'lmtp'
concurrency = 5

[remote.lmtp.tls]
implicit = true
allow-invalid-certs = true
";

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
    let mut core = SMTP::test();
    core.core.smtp.session.rcpt.relay = IfBlock::new(true);
    core.core.smtp.session.extensions.dsn = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("lmtp_delivery_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Lmtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.core.smtp.resolvers.dns.ipv4_add(
        "lmtp.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Multiple delivery attempts
    let mut local_qr = core.init_test_queue("lmtp_delivery_local");
    core.core.storage.relay_hosts.insert(
        "lmtp".to_string(),
        Config::new(REMOTE).unwrap().parse_host("lmtp").unwrap(),
    );
    core.core.smtp.queue.next_hop = r#"[{if = "rcpt_domain = 'foobar.org'", then = "'lmtp'"},
    {else = false}]"#
        .parse_if();
    core.core.smtp.session.rcpt.relay = IfBlock::new(true);
    core.core.smtp.session.rcpt.max_recipients = IfBlock::new(100);
    core.core.smtp.session.extensions.dsn = IfBlock::new(true);
    let config = &mut core.core.smtp.queue;
    config.retry = IfBlock::new(Duration::from_secs(1));
    config.notify = r#"[{if = "rcpt_domain = 'foobar.org'", then = "[1s, 2s]"},
    {else = [1s]}]"#
        .parse_if();
    config.expire = r#"[{if = "rcpt_domain = 'foobar.org'", then = "4s"},
    {else = "5s"}]"#
        .parse_if();
    config.timeout.data = IfBlock::new(Duration::from_millis(50));

    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
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
    local_qr
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone())
        .await;
    let mut dsn = Vec::new();
    loop {
        match local_qr.try_read_event().await {
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
    local_qr.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 4);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("<jane@foobar.org> (delivered to")
        .assert_contains("<john@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.org> (host 'lmtp.foobar.org' rejected command");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: failed");

    assert_eq!(
        remote_qr
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
    remote_qr.assert_no_events();
}
