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

use common::{config::server::ServerProtocol, expr::if_block::IfBlock};
use mail_auth::MX;
use store::write::now;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    core::{Session, SMTP},
    queue::{DeliveryAttempt, Event},
};

const SMUGGLER: &str = r#"From: Joe SixPack <john@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: Is dinner ready?

Hi.

We lost the game. Are you hungry yet?
.hey
Joe.

<SEP>.
MAIL FROM:<admin@foobar.net>
RCPT TO:<ok@foobar.org>
DATA
From: Joe SixPack <admin@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: smuggled message

This is a smuggled message
"#;

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
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
    core.core.smtp.session.extensions.chunking = IfBlock::new(false);
    let mut remote_qr = core.init_test_queue("smtp_delivery_remote");
    let remote_core = Arc::new(core);
    let _rx = start_test_server(remote_core.clone(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    for domain in ["foobar.org", "foobar.net", "foobar.com"] {
        core.core.smtp.resolvers.dns.mx_add(
            domain,
            vec![MX {
                exchanges: vec![format!("mx1.{domain}"), format!("mx2.{domain}")],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(10),
        );
        core.core.smtp.resolvers.dns.ipv4_add(
            format!("mx1.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
        core.core.smtp.resolvers.dns.ipv4_add(
            format!("mx2.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
    }

    // Multiple delivery attempts
    let mut local_qr = core.init_test_queue("smtp_delivery_local");
    core.core.smtp.session.rcpt.relay = IfBlock::new(true);
    core.core.smtp.session.rcpt.max_recipients = IfBlock::new(100);
    core.core.smtp.session.extensions.dsn = IfBlock::new(true);
    let config = &mut core.core.smtp.queue;
    config.retry = IfBlock::new(Duration::from_secs(1));
    config.notify = r#"[{if = "rcpt_domain = 'foobar.org'", then = "[1s, 2s]"},
    {if = "rcpt_domain = 'foobar.com'", then = "[5s, 6s]"},
    {else = [1s]}]"#
        .parse_if();
    config.expire = r#"[{if = "rcpt_domain = 'foobar.org'", then = "6s"},
    {else = "7s"}]"#
        .parse_if();

    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<ok@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<ok@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    let message = local_qr.expect_message().await;
    let num_domains = message.domains.len();
    assert_eq!(num_domains, 3);
    local_qr
        .delivery_attempt(message.id)
        .await
        .try_deliver(core.clone())
        .await;
    let mut dsn = Vec::new();
    let mut domain_retries = vec![0; num_domains];
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
                for (idx, domain) in message.domains.iter().enumerate() {
                    domain_retries[idx] = domain.retry.inner;
                }
                DeliveryAttempt::new(event).try_deliver(core.clone()).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert_eq!(domain_retries[0], 0, "retries {domain_retries:?}");
    assert!(domain_retries[1] >= 5, "retries {domain_retries:?}");
    assert!(domain_retries[2] >= 5, "retries {domain_retries:?}");
    assert!(
        domain_retries[1] >= domain_retries[2],
        "retries {domain_retries:?}"
    );

    local_qr.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 5);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<ok@foobar.net> (delivered to")
        .assert_contains("<ok@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.net> (host ")
        .assert_contains("<fail@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local_qr)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("Action: failed");

    assert_eq!(
        remote_qr
            .consume_message(&remote_core)
            .await
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["ok@foobar.org".to_string()]
    );
    assert_eq!(
        remote_qr
            .consume_message(&remote_core)
            .await
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["ok@foobar.net".to_string()]
    );

    remote_qr.assert_no_events();

    // SMTP smuggling
    for separator in ["\n", "\r"].iter() {
        session.data.remote_ip_str = "10.0.0.2".to_string();
        session.eval_session_params().await;
        session.ehlo("mx.test.org").await;

        let message = SMUGGLER
            .replace('\r', "")
            .replace('\n', "\r\n")
            .replace("<SEP>", separator);

        session
            .send_message("john@doe.org", &["bill@foobar.com"], &message, "250")
            .await;
        local_qr
            .expect_message_then_deliver()
            .await
            .try_deliver(core.clone())
            .await;
        local_qr.read_event().await.assert_reload();

        let message = remote_qr
            .consume_message(&remote_core)
            .await
            .read_message(&remote_qr)
            .await;

        assert!(
            message.contains("This is a smuggled message"),
            "message: {:?}",
            message
        );
        assert!(
            message.contains("We lost the game."),
            "message: {:?}",
            message
        );
        assert!(
            message.contains(&format!("{separator}..\r\nMAIL FROM:<",)),
            "message: {:?}",
            message
        );
    }
}
