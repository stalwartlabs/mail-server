/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use mail_auth::MX;
use utils::config::ServerProtocol;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    config::{ConfigContext, IfBlock},
    core::{Session, SMTP},
    queue::{manager::Queue, DeliveryAttempt, Event, WorkerResult},
};

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_delivery_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![
            MX {
                exchanges: vec!["mx1.foobar.org".to_string()],
                preference: 10,
            },
            MX {
                exchanges: vec!["mx2.foobar.org".to_string()],
                preference: 20,
            },
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.mx_add(
        "foobar.net",
        vec![MX {
            exchanges: vec!["mx1.foobar.net".to_string(), "mx2.foobar.net".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.net",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Multiple delivery attempts
    let mut local_qr = core.init_test_queue("smtp_delivery_local");
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.rcpt.max_recipients = IfBlock::new(100);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let mut config = &mut core.queue.config;
    config.retry = IfBlock::new(vec![Duration::from_millis(100)]);
    config.notify = "[{if = 'rcpt-domain', eq = 'foobar.org', then = ['100ms', '200ms']},
    {else = ['100ms']}]"
        .parse_if(&ConfigContext::new(&[]));
    config.expire = "[{if = 'rcpt-domain', eq = 'foobar.org', then = '650ms'},
    {else = '750ms'}]"
        .parse_if(&ConfigContext::new(&[]));

    let core = Arc::new(core);
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
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
    let message = local_qr.read_event().await.unwrap_message();
    let num_domains = message.domains.len();
    assert_eq!(num_domains, 3);
    DeliveryAttempt::from(message)
        .try_deliver(core.clone(), &mut queue)
        .await;
    let mut dsn = Vec::new();
    let mut domain_retries = vec![0; num_domains];
    loop {
        match local_qr.try_read_event().await {
            Some(Event::Queue(message)) => {
                dsn.push(message.inner);
            }
            Some(Event::Done(wr)) => match wr {
                WorkerResult::Done => {
                    break;
                }
                WorkerResult::Retry(retry) => {
                    for (idx, domain) in retry.inner.domains.iter().enumerate() {
                        domain_retries[idx] = domain.retry.inner;
                    }
                    queue.schedule(retry);
                }
                WorkerResult::OnHold(_) => unreachable!(),
            },
            None | Some(Event::Stop) => break,
            Some(Event::Manage(_)) => unreachable!(),
        }

        if !queue.scheduled.is_empty() {
            tokio::time::sleep(queue.wake_up_time()).await;
            DeliveryAttempt::from(queue.next_due().unwrap())
                .try_deliver(core.clone(), &mut queue)
                .await;
        }
    }
    assert_eq!(domain_retries[0], 0, "retries {domain_retries:?}");
    assert!(domain_retries[1] >= 5, "retries {domain_retries:?}");
    assert!(domain_retries[2] >= 5, "retries {domain_retries:?}");
    assert!(
        domain_retries[1] >= domain_retries[2],
        "retries {domain_retries:?}"
    );

    assert!(queue.scheduled.is_empty());
    assert_eq!(dsn.len(), 5);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<ok@foobar.net> (delivered to")
        .assert_contains("<ok@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.net> (host ")
        .assert_contains("<fail@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines()
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("Action: failed");

    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["ok@foobar.net".to_string()]
    );
    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["ok@foobar.org".to_string()]
    );

    remote_qr.assert_empty_queue();
}
