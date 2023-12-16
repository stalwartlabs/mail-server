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

use ahash::{AHashMap, HashMap, HashSet};
use directory::config::ConfigDirectory;
use mail_auth::MX;
use mail_parser::DateTime;
use reqwest::{header::AUTHORIZATION, StatusCode};
use store::Stores;
use utils::config::{Config, ServerProtocol};

use crate::smtp::{
    inbound::TestQueueEvent, management::send_manage_request, outbound::start_test_server,
    session::TestSession, TestConfig, TestSMTP,
};
use smtp::{
    config::IfBlock,
    core::{management::Message, Session, SMTP},
    queue::{
        manager::{Queue, SpawnQueue},
        QueueId, Status,
    },
};

const DIRECTORY: &str = r#"
[directory."local"]
type = "memory"

[directory."local".options]
superuser-group = "superusers"

[[directory."local".principals]]
name = "admin"
description = "Superuser"
secret = "secret"
member-of = ["superusers"]

"#;

#[tokio::test]
#[serial_test::serial]
async fn manage_queue() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start remote test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_manage_queue_remote");
    let _rx_remote = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx1.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );

    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Start local management interface
    let directory = Config::new(DIRECTORY)
        .unwrap()
        .parse_directory(&Stores::default(), None)
        .unwrap();
    core.queue.config.management_lookup = directory.directories.get("local").unwrap().clone();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.rcpt.max_recipients = IfBlock::new(100);
    core.session.config.extensions.future_release = IfBlock::new(Some(Duration::from_secs(86400)));
    core.session.config.extensions.dsn = IfBlock::new(true);
    core.queue.config.retry = IfBlock::new(vec![Duration::from_secs(1000)]);
    core.queue.config.notify = IfBlock::new(vec![Duration::from_secs(2000)]);
    core.queue.config.expire = IfBlock::new(Duration::from_secs(3000));
    let local_qr = core.init_test_queue("smtp_manage_queue_local");
    let core = Arc::new(core);
    local_qr.queue_rx.spawn(core.clone(), Queue::default());
    let _rx_manage = start_test_server(core.clone(), &[ServerProtocol::Http]);

    // Send test messages
    let envelopes = HashMap::from_iter([
        (
            "a",
            (
                "bill1@foobar.net",
                vec![
                    "rcpt1@example1.org",
                    "rcpt1@example2.org",
                    "rcpt1@example2.org",
                ],
            ),
        ),
        (
            "b",
            (
                "bill2@foobar.net",
                vec!["rcpt3@example1.net", "rcpt4@example1.net"],
            ),
        ),
        (
            "c",
            (
                "bill3@foobar.net",
                vec![
                    "rcpt5@example1.com",
                    "rcpt6@example2.com",
                    "rcpt7@example2.com",
                    "rcpt8@example3.com",
                    "rcpt9@example4.com",
                ],
            ),
        ),
        ("d", ("bill4@foobar.net", vec!["delay@foobar.org"])),
        ("e", ("bill5@foobar.net", vec!["john@foobar.org"])),
        ("f", ("", vec!["success@foobar.org", "delay@foobar.org"])),
    ]);
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("foobar.net").await;
    for test_num in 0..6 {
        let env_id = char::from(b'a' + test_num).to_string();
        let hold_for = ((test_num + 1) as u32) * 100;
        let (sender, recipients) = envelopes.get(env_id.as_str()).unwrap();
        session
            .send_message(
                &if env_id != "f" {
                    format!("<{sender}> ENVID={env_id} HOLDFOR={hold_for}")
                } else {
                    format!("<{sender}> ENVID={env_id}")
                },
                recipients,
                "test:no_dkim",
                "250",
            )
            .await;
    }

    // Expect delivery to success@foobar.org
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["success@foobar.org".to_string()]
    );

    // Fetch and validate messages
    let ids = send_manage_request::<Vec<QueueId>>("/admin/queue/list")
        .await
        .unwrap()
        .unwrap_data();
    assert_eq!(ids.len(), 6);
    let mut id_map = AHashMap::new();
    let mut id_map_rev = AHashMap::new();
    let mut test_search = String::new();
    for (message, id) in get_messages(&ids).await.into_iter().zip(ids) {
        let message = message.unwrap();
        let env_id = message.env_id.as_ref().unwrap().clone();

        // Validate return path and recipients
        let (sender, recipients) = envelopes.get(env_id.as_str()).unwrap();
        assert_eq!(&message.return_path, sender);
        'outer: for recipient in recipients {
            for domain in &message.domains {
                for rcpt in &domain.recipients {
                    if &rcpt.address == recipient {
                        continue 'outer;
                    }
                }
            }
            panic!("Recipient {recipient} not found in message.");
        }

        // Validate status and datetimes
        let created = message.created.to_timestamp();
        let hold_for = (env_id.as_bytes().first().unwrap() - b'a' + 1) as i64 * 100;
        let next_retry = created + hold_for;
        let next_notify = created + 2000 + hold_for;
        let expires = created + 3000 + hold_for;
        for domain in &message.domains {
            if env_id == "c" {
                test_search = domain.next_retry.as_ref().unwrap().to_rfc3339();
            }
            if env_id != "f" {
                assert_eq!(domain.retry_num, 0);
                assert_timestamp(
                    domain.next_retry.as_ref().unwrap(),
                    next_retry,
                    "retry",
                    &message,
                );
                assert_timestamp(
                    domain.next_notify.as_ref().unwrap(),
                    next_notify,
                    "notify",
                    &message,
                );
                assert_timestamp(&domain.expires, expires, "expires", &message);
                for rcpt in &domain.recipients {
                    assert_eq!(&rcpt.status, &Status::Scheduled, "{message:#?}");
                }
            } else {
                assert_eq!(domain.retry_num, 1);
                for rcpt in &domain.recipients {
                    if rcpt.address == "success@foobar.org" {
                        assert!(
                            matches!(&rcpt.status, Status::Completed(_)),
                            "{:?}",
                            rcpt.status
                        );
                    } else {
                        assert!(
                            matches!(&rcpt.status, Status::TemporaryFailure(_)),
                            "{:?}",
                            rcpt.status
                        );
                    }
                }
            }
        }

        id_map.insert(env_id.clone(), id);
        id_map_rev.insert(id, env_id);
    }
    assert_eq!(id_map.len(), 6);

    // Test list search
    for (query, expected_ids) in [
        (
            "/admin/queue/list?from=bill1@foobar.net".to_string(),
            vec!["a"],
        ),
        (
            "/admin/queue/list?to=foobar.org".to_string(),
            vec!["d", "e", "f"],
        ),
        (
            "/admin/queue/list?from=bill3@foobar.net&to=rcpt5@example1.com".to_string(),
            vec!["c"],
        ),
        (
            format!("/admin/queue/list?before={test_search}"),
            vec!["a", "b"],
        ),
        (
            format!("/admin/queue/list?after={test_search}"),
            vec!["d", "e", "f", "c"],
        ),
    ] {
        let expected_ids = HashSet::from_iter(expected_ids.into_iter().map(|s| s.to_string()));
        let ids = send_manage_request::<Vec<QueueId>>(&query)
            .await
            .unwrap()
            .unwrap_data()
            .into_iter()
            .map(|id| id_map_rev.get(&id).unwrap().clone())
            .collect::<HashSet<_>>();
        assert_eq!(ids, expected_ids, "failed for {query}");
    }

    // Retry delivery
    assert_eq!(
        send_manage_request::<Vec<bool>>(&format!(
            "/admin/queue/retry?id={},{}",
            id_map.get("e").unwrap(),
            id_map.get("f").unwrap()
        ))
        .await
        .unwrap()
        .unwrap_data(),
        vec![true, true]
    );
    assert_eq!(
        send_manage_request::<Vec<bool>>(&format!(
            "/admin/queue/retry?id={}&filter=example1.org&at=2200-01-01T00:00:00Z",
            id_map.get("a").unwrap(),
        ))
        .await
        .unwrap()
        .unwrap_data(),
        vec![true]
    );

    // Expect delivery to john@foobar.org
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        remote_qr
            .read_event()
            .await
            .unwrap_message()
            .recipients
            .into_iter()
            .map(|r| r.address)
            .collect::<Vec<_>>(),
        vec!["john@foobar.org".to_string()]
    );

    // Message 'e' should be gone, 'f' should have retry_num == 2
    // while 'a' should have a retry time of 2200-01-01T00:00:00Z for example1.org
    let mut messages = get_messages(&[
        *id_map.get("e").unwrap(),
        *id_map.get("f").unwrap(),
        *id_map.get("a").unwrap(),
    ])
    .await
    .into_iter();
    assert_eq!(messages.next().unwrap(), None);
    assert_eq!(
        messages
            .next()
            .unwrap()
            .unwrap()
            .domains
            .first()
            .unwrap()
            .retry_num,
        2
    );
    for domain in messages.next().unwrap().unwrap().domains {
        let next_retry = domain.next_retry.as_ref().unwrap().to_rfc3339();
        let matched =
            ["2200-01-01T00:00:00Z", "2199-12-31T23:59:59Z"].contains(&next_retry.as_str());
        if domain.name == "example1.org" {
            assert!(matched, "{next_retry}");
        } else {
            assert!(!matched, "{next_retry}");
        }
    }

    // Cancel deliveries
    for (id, filter) in [
        ("a", "example2.org"),
        ("b", "example1.net"),
        ("c", "rcpt6@example2.com"),
        ("d", ""),
    ] {
        assert_eq!(
            send_manage_request::<Vec<bool>>(&format!(
                "/admin/queue/cancel?id={}{}{}",
                id_map.get(id).unwrap(),
                if !filter.is_empty() { "&filter=" } else { "" },
                filter
            ))
            .await
            .unwrap()
            .unwrap_data(),
            vec![true],
            "failed for {id}: {filter}"
        );
    }
    assert_eq!(
        send_manage_request::<Vec<QueueId>>("/admin/queue/list")
            .await
            .unwrap()
            .unwrap_data()
            .len(),
        3
    );
    for (message, id) in get_messages(&[
        *id_map.get("a").unwrap(),
        *id_map.get("b").unwrap(),
        *id_map.get("c").unwrap(),
        *id_map.get("d").unwrap(),
    ])
    .await
    .into_iter()
    .zip(["a", "b", "c", "d"])
    {
        if ["b", "d"].contains(&id) {
            assert_eq!(message, None);
        } else {
            let message = message.unwrap();
            assert!(!message.domains.is_empty());
            for domain in message.domains {
                match id {
                    "a" => {
                        if domain.name == "example2.org" {
                            assert_eq!(&domain.status, &Status::Completed("".to_string()));
                            for rcpt in &domain.recipients {
                                assert!(matches!(&rcpt.status, Status::Completed(_)));
                            }
                        } else {
                            assert_eq!(&domain.status, &Status::Scheduled);
                            for rcpt in &domain.recipients {
                                assert!(matches!(&rcpt.status, Status::Scheduled));
                            }
                        }
                    }
                    "c" => {
                        assert_eq!(&domain.status, &Status::Scheduled);
                        if domain.name == "example2.com" {
                            for rcpt in &domain.recipients {
                                if rcpt.address == "rcpt6@example2.com" {
                                    assert!(matches!(&rcpt.status, Status::Completed(_)));
                                } else {
                                    assert!(matches!(&rcpt.status, Status::Scheduled));
                                }
                            }
                        } else {
                            for rcpt in &domain.recipients {
                                assert!(matches!(&rcpt.status, Status::Scheduled));
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    // Test authentication error
    assert_eq!(
        reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .get("https://127.0.0.1:9980/list")
            .header(AUTHORIZATION, "Basic YWRtaW46aGVsbG93b3JsZA==")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

fn assert_timestamp(timestamp: &DateTime, expected: i64, ctx: &str, message: &Message) {
    let timestamp = timestamp.to_timestamp();
    let diff = timestamp - expected;
    if ![-2, -1, 0, 1, 2].contains(&diff) {
        panic!("Got timestamp {timestamp}, expected {expected} (diff {diff} for {ctx}) for {message:?}");
    }
}

async fn get_messages(ids: &[QueueId]) -> Vec<Option<Message>> {
    send_manage_request(&format!(
        "/admin/queue/status?id={}",
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    ))
    .await
    .unwrap()
    .unwrap_data()
}
