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
use smtp_proto::{MAIL_REQUIRETLS, MAIL_RET_HDRS, MAIL_SMTPUTF8, RCPT_NOTIFY_NEVER};
use utils::config::ServerProtocol;

use crate::smtp::{
    inbound::{TestMessage, TestQueueEvent},
    outbound::start_test_server,
    session::{TestSession, VerifyResponse},
    TestConfig, TestSMTP,
};
use smtp::{
    config::IfBlock,
    core::{Session, SMTP},
    queue::{manager::Queue, DeliveryAttempt},
};

#[tokio::test]
#[serial_test::serial]
async fn extensions() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.data.max_message_size = IfBlock::new(1500);
    core.session.config.extensions.dsn = IfBlock::new(true);
    core.session.config.extensions.requiretls = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_ext_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    // Add mock DNS entries
    let mut core = SMTP::test();
    core.resolvers.dns.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".to_string()],
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Successful delivery with DSN
    let mut local_qr = core.init_test_queue("smtp_ext_local");
    core.session.config.rcpt.relay = IfBlock::new(true);
    core.session.config.extensions.dsn = IfBlock::new(true);
    let core = Arc::new(core);
    let mut queue = Queue::default();
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &["<bill@foobar.org> NOTIFY=SUCCESS,FAILURE"],
            "test:no_dkim",
            "250",
        )
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;

    local_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: delivered");
    local_qr.read_event().await.unwrap_done();
    remote_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("using TLSv1.3 with cipher");

    // Test SIZE extension
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:arc", "250")
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr
        .read_event()
        .await
        .unwrap_message()
        .read_lines()
        .assert_contains("<bill@foobar.org> (host 'mx.foobar.org' rejected command 'MAIL FROM:")
        .assert_contains("Action: failed")
        .assert_contains("Diagnostic-Code: smtp;552")
        .assert_contains("Status: 5.3.4");
    local_qr.read_event().await.unwrap_done();
    remote_qr.assert_empty_queue();

    // Test DSN, SMTPUTF8 and REQUIRETLS extensions
    session
        .send_message(
            "<john@test.org> ENVID=abc123 RET=HDRS REQUIRETLS SMTPUTF8",
            &["<bill@foobar.org> NOTIFY=NEVER"],
            "test:no_dkim",
            "250",
        )
        .await;
    DeliveryAttempt::from(local_qr.read_event().await.unwrap_message())
        .try_deliver(core.clone(), &mut queue)
        .await;
    local_qr.read_event().await.unwrap_done();
    let message = remote_qr.read_event().await.unwrap_message();
    assert_eq!(message.env_id, Some("abc123".to_string()));
    assert!((message.flags & MAIL_RET_HDRS) != 0);
    assert!((message.flags & MAIL_REQUIRETLS) != 0);
    assert!((message.flags & MAIL_SMTPUTF8) != 0);
    assert!((message.recipients.last().unwrap().flags & RCPT_NOTIFY_NEVER) != 0);
}
