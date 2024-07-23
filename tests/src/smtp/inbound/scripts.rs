/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use core::panic;
use std::{fmt::Write, fs, path::PathBuf};

use crate::smtp::{
    build_smtp,
    inbound::{sign::SIGNATURES, TestMessage, TestQueueEvent},
    session::{TestSession, VerifyResponse},
    TempDir, TestSMTP,
};
use common::Core;

use smtp::{
    core::{Inner, Session},
    scripts::ScriptResult,
};
use store::Stores;
use utils::config::Config;

const CONFIG: &str = r#"
[storage]
data = "sql"
lookup = "sql"
blob = "sql"
fts = "sql"

[store."sql"]
type = "sqlite"
path = "{TMP}/smtp_sieve.db"

[store."sql".pool]
max-connections = 10
min-connections = 0
idle-timeout = "5m"

[session.data.pipe."test"]
command = [ { if = "remote_ip = '10.0.0.123'", then = "'/bin/bash'" }, 
            { else = false } ]
arguments = "['{CFG_PATH}/pipe_me.sh', 'hello', 'world']"
timeout = "10s"

[sieve.trusted]
from-name = "'Sieve Daemon'"
from-addr = "'sieve@foobar.org'"
return-path = "''"
hostname = "mx.foobar.org"
sign = "['rsa']"

[sieve.trusted.limits]
redirects = 3
out-messages = 5
received-headers = 50
cpu = 10000
nested-includes = 5
duplicate-expiry = "7d"

[session.connect]
script = "'stage_connect'"
greeting = "'mx.example.org at your service'"

[session.ehlo]
script = "'stage_ehlo'"

[session.mail]
script = "'stage_mail'"

[session.rcpt]
script = "'stage_rcpt'"
relay = true

[session.data]
script = "'stage_data'"

[session.data.add-headers]
received = true
received-spf = true
auth-results = true
message-id = true
date = true
return-path = false

"#;

#[tokio::test]
async fn sieve_scripts() {
    /*let disable = 1;
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Add test scripts
    let mut config = CONFIG.to_string() + SIGNATURES;
    for entry in fs::read_dir(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("smtp")
            .join("sieve"),
    )
    .unwrap()
    {
        let entry = entry.unwrap();
        writeln!(
            &mut config,
            "[sieve.trusted.scripts.{}]\ncontents = \"%{{file:{}}}%\"",
            entry
                .file_name()
                .to_str()
                .unwrap()
                .split_once('.')
                .unwrap()
                .0,
            entry.path().to_str().unwrap()
        )
        .unwrap();
    }

    // Prepare config
    let mut inner = Inner::default();
    let tmp_dir = TempDir::new("smtp_sieve_test", true);
    let mut config = Config::new(
        tmp_dir.update_config(
            config.replace(
                "{CFG_PATH}",
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("smtp")
                    .join("pipe")
                    .as_path()
                    .to_str()
                    .unwrap(),
            ),
        ),
    )
    .unwrap();
    config.resolve_all_macros().await;
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let mut qr = inner.init_test_queue(&core);

    // Build session
    let core = build_smtp(core, inner);
    let mut session = Session::test(core.clone());
    session.data.remote_ip_str = "10.0.0.88".parse().unwrap();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    assert!(!session.init_conn().await);

    // Run tests
    for (name, script) in &core.core.sieve.scripts {
        if name.starts_with("stage_") || name.ends_with("_include") {
            continue;
        }
        let script = script.clone();
        let params = session
            .build_script_parameters("data")
            .set_variable("from", "john.doe@example.org")
            .with_envelope(&core.core, &session, 0)
            .await;
        let core_ = core.clone();
        match core_.run_script(script, params, 0).await {
            ScriptResult::Accept { .. } => (),
            ScriptResult::Reject(message) => panic!("{}", message),
            err => {
                panic!("Unexpected script result {err:?}");
            }
        }
    }

    // Test connect script
    session
        .response()
        .assert_contains("503 5.5.3 Your IP '10.0.0.88' is not welcomed here");
    session.data.remote_ip_str = "10.0.0.5".parse().unwrap();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    assert!(session.init_conn().await);
    session
        .response()
        .assert_contains("220 mx.example.org at your service");

    // Test EHLO script
    session
        .cmd(
            "EHLO spammer.org",
            "551 5.1.1 Your domain 'spammer.org' has been blocklisted",
        )
        .await;
    session.cmd("EHLO foobar.net", "250").await;

    // Test MAIL-FROM script
    session
        .mail_from("spammer@domain.com", "450 4.1.1 Invalid address")
        .await;
    session
        .mail_from(
            "marketing@spam-domain.com",
            "503 5.5.3 Your address has been blocked",
        )
        .await;
    session.mail_from("bill@foobar.org", "250").await;

    // Test RCPT-TO script
    session
        .rcpt_to(
            "jane@foobar.org",
            "422 4.2.2 You have been greylisted '10.0.0.5.bill@foobar.org.jane@foobar.org'.",
        )
        .await;
    session.rcpt_to("jane@foobar.org", "250").await;

    // Expect a modified message
    session.data("test:multipart", "250").await;

    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT");
    qr.assert_no_events();

    // Expect rejection for bill@foobar.net
    session
        .send_message(
            "test@example.net",
            &["bill@foobar.net"],
            "test:multipart",
            "503 5.5.3 Bill cannot receive messages",
        )
        .await;
    qr.assert_no_events();
    qr.clear_queue(&core).await;

    // Expect message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["john@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;
    qr.read_event().await.assert_reload();
    qr.read_event().await.assert_reload();
    let messages = qr.read_queued_messages().await;
    assert_eq!(messages.len(), 2);
    let mut messages = messages.into_iter();
    let notification = messages.next().unwrap();
    assert_eq!(notification.return_path, "");
    assert_eq!(notification.recipients.len(), 2);
    assert_eq!(
        notification.recipients.first().unwrap().address,
        "john@example.net"
    );
    assert_eq!(
        notification.recipients.last().unwrap().address,
        "jane@example.org"
    );
    notification
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");

    messages
        .next()
        .unwrap()
        .read_lines(&qr)
        .await
        .assert_contains("One Two Three Four")
        .assert_contains("multi-part message in MIME format")
        .assert_not_contains("X-Part-Number: 5")
        .assert_not_contains("THIS IS A PIECE OF HTML TEXT");
    qr.assert_no_events();
    qr.clear_queue(&core).await;

    // Expect a modified message delivery plus a notification
    session
        .send_message(
            "test@example.net",
            &["jane@foobar.net"],
            "test:multipart",
            "250",
        )
        .await;
    qr.read_event().await.assert_reload();
    qr.read_event().await.assert_reload();
    let messages = qr.read_queued_messages().await;
    assert_eq!(messages.len(), 2);
    let mut messages = messages.into_iter();

    messages
        .next()
        .unwrap()
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("From: \"Sieve Daemon\" <sieve@foobar.org>")
        .assert_contains("To: <john@example.net>")
        .assert_contains("Cc: <jane@example.org>")
        .assert_contains("Subject: You have got mail")
        .assert_contains("One Two Three Four");

    messages
        .next()
        .unwrap()
        .read_lines(&qr)
        .await
        .assert_contains("X-Part-Number: 5")
        .assert_contains("THIS IS A PIECE OF HTML TEXT")
        .assert_not_contains("X-My-Header: true");
    qr.clear_queue(&core).await;

    // Expect a modified redirected message
    session
        .send_message(
            "test@example.net",
            &["thomas@foobar.gov"],
            "test:no_dkim",
            "250",
        )
        .await;

    let redirect = qr.expect_message().await;
    assert_eq!(redirect.return_path, "");
    assert_eq!(redirect.recipients.len(), 1);
    assert_eq!(
        redirect.recipients.first().unwrap().address,
        "redirect@here.email"
    );
    redirect
        .read_lines(&qr)
        .await
        .assert_contains("From: no-reply@my.domain")
        .assert_contains("To: Suzie Q <suzie@shopping.example.net>")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Message-ID: <20030712040037.46341.5F8J@football.example.com>")
        .assert_contains("Received: ")
        .assert_not_contains("From: Joe SixPack <joe@football.example.com>");
    qr.assert_no_events();

    // Expect an intact redirected message
    session
        .send_message(
            "test@example.net",
            &["bob@foobar.gov"],
            "test:no_dkim",
            "250",
        )
        .await;

    let redirect = qr.expect_message().await;
    assert_eq!(redirect.return_path, "");
    assert_eq!(redirect.recipients.len(), 1);
    assert_eq!(
        redirect.recipients.first().unwrap().address,
        "redirect@somewhere.email"
    );
    redirect
        .read_lines(&qr)
        .await
        .assert_not_contains("From: no-reply@my.domain")
        .assert_contains("To: Suzie Q <suzie@shopping.example.net>")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Message-ID: <20030712040037.46341.5F8J@football.example.com>")
        .assert_contains("From: Joe SixPack <joe@football.example.com>")
        .assert_contains("Received: ")
        .assert_contains("Authentication-Results: ");
    qr.assert_no_events();

    // Test pipes
    session.data.remote_ip_str = "10.0.0.123".parse().unwrap();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
    session
        .send_message(
            "test@example.net",
            &["pipe@foobar.com"],
            "test:no_dkim",
            "250",
        )
        .await;

    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-My-Header: true")
        .assert_contains("Authentication-Results");
    qr.assert_no_events();
}
