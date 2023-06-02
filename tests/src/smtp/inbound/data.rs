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

use directory::config::ConfigDirectory;
use utils::config::Config;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    session::{load_test_message, TestSession, VerifyResponse},
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    config::{ConfigContext, IfBlock},
    core::{Session, SMTP},
};

const DIRECTORY: &str = r#"
[directory."local"]
type = "memory"

[[directory."local".users]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["john@foobar.org", "jdoe@example.org", "john.doe@example.org"]

[[directory."local".users]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@domain.net"

[[directory."local".users]]
name = "bill"
description = "Bill Foobar"
secret = "p4ssw0rd"
email = "bill@foobar.org"

[[directory."local".users]]
name = "mike"
description = "Mike Foobar"
secret = "p4ssw0rd"
email = "mike@test.com"

[directory."local".lookup]
domains = ["foobar.org", "domain.net", "test.com"]
"#;

#[tokio::test]
async fn data() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/
    let mut core = SMTP::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_data_test");
    let directory = Config::parse(DIRECTORY).unwrap().parse_directory().unwrap();
    let mut config = &mut core.session.config.rcpt;
    config.lookup_domains = IfBlock::new(Some(
        directory.lookups.get("local/domains").unwrap().clone(),
    ));
    config.directory = IfBlock::new(Some(directory.directories.get("local").unwrap().clone()));

    let mut config = &mut core.session.config;
    config.data.add_auth_results = "[{if = 'remote-ip', eq = '10.0.0.3', then = true},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.data.add_date = config.data.add_auth_results.clone();
    config.data.add_message_id = config.data.add_auth_results.clone();
    config.data.add_received = config.data.add_auth_results.clone();
    config.data.add_return_path = config.data.add_auth_results.clone();
    config.data.add_received_spf = config.data.add_auth_results.clone();
    config.data.max_received_headers = IfBlock::new(3);
    config.data.max_messages = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 1},
    {else = 100}]"
        .parse_if(&ConfigContext::new(&[]));

    core.queue.config.quota = r"[[queue.quota]]
    match = {if = 'sender', eq = 'john@doe.org'}
    key = ['sender']
    messages = 1

    [[queue.quota]]
    match = {if = 'rcpt-domain', eq = 'foobar.org'}
    key = ['rcpt-domain']
    size = 450

    [[queue.quota]]
    match = {if = 'rcpt', eq = 'jane@domain.net'}
    key = ['rcpt']
    size = 450
    "
    .parse_quota(&ConfigContext::new(&[]));

    // Test queue message builder
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.test_builder().await;

    // Send DATA without RCPT
    session.ehlo("mx.doe.org").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("503 5.5.1");

    // Send broken message
    session
        .send_message(
            "john@doe.org",
            &["bill@foobar.org"],
            "From: john",
            "550 5.7.7",
        )
        .await;

    // Naive Loop detection
    session
        .send_message(
            "john@doe.org",
            &["bill@foobar.org"],
            "test:loop",
            "450 4.4.6",
        )
        .await;

    // No headers should be added to messages from 10.0.0.1
    session
        .send_message("john@doe.org", &["bill@foobar.org"], "test:no_msgid", "250")
        .await;
    assert_eq!(
        qr.read_event().await.unwrap_message().read_message(),
        load_test_message("no_msgid", "messages")
    );

    // Maximum one message per session is allowed for 10.0.0.1
    session.mail_from("john@doe.org", "250").await;
    session.rcpt_to("bill@foobar.org", "250").await;
    session.ingest(b"DATA\r\n").await.unwrap();
    session.response().assert_code("451 4.4.5");
    session.rset().await;

    // Headers should be added to messages from 10.0.0.3
    session.data.remote_ip = "10.0.0.3".parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message("john@doe.org", &["mike@test.com"], "test:no_msgid", "250")
        .await;
    qr.read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("From: ")
        .assert_contains("To: ")
        .assert_contains("Subject: ")
        .assert_contains("Date: ")
        .assert_contains("Message-ID: ")
        .assert_contains("Return-Path: ")
        .assert_contains("Received: ")
        .assert_contains("Authentication-Results: ")
        .assert_contains("Received-SPF: ");

    // Only one message is allowed in the queue from john@doe.org
    let mut queued_messages = vec![];
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .send_message("john@doe.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    queued_messages.push(qr.read_event().await);
    session
        .send_message(
            "john@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Release quota
    queued_messages.clear();

    // Only 1500 bytes are allowed in the queue to domain foobar.org
    session
        .send_message(
            "jane@foobar.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250",
        )
        .await;
    queued_messages.push(qr.read_event().await);
    session
        .send_message(
            "jane@foobar.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;

    // Only 1500 bytes are allowed in the queue to recipient jane@domain.net
    session
        .send_message(
            "jane@foobar.org",
            &["jane@domain.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    queued_messages.push(qr.read_event().await);
    session
        .send_message(
            "jane@foobar.org",
            &["jane@domain.net"],
            "test:no_dkim",
            "452 4.3.1",
        )
        .await;
}
