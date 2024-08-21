/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Core;

use store::Stores;
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    session::{TestSession, VerifyResponse},
    TempDir,
};
use smtp::core::{Inner, Session, State};

const CONFIG: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["john@example.org", "jdoe@example.org", "john.doe@example.org"]
email-list = ["info@example.org"]
member-of = ["sales"]

[[directory."local".principals]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@example.org"
email-list = ["info@example.org"]
member-of = ["sales", "support"]

[session.auth]
require = [{if = "remote_ip = '10.0.0.1'", then = true},
           {else = false}]
mechanisms = [{if = "remote_ip = '10.0.0.1' && is_tls", then = "[plain, login]"},
              {else = 0}]
directory = [{if = "remote_ip = '10.0.0.1'", then = "'local'"},
             {else = false}]
must-match-sender = true

[session.auth.errors]
total = [{if = "remote_ip = '10.0.0.1'", then = 2},
              {else = 3}]
wait = "100ms"

[session.extensions]
future-release = [{if = '!is_empty(authenticated_as)', then = '1d'},
                  {else = false}]
"#;

#[tokio::test]
async fn auth() {
    // Enable logging
    crate::enable_logging();

    let tmp_dir = TempDir::new("smtp_auth_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;

    // EHLO should not advertise plain text auth without TLS
    let mut session = Session::test(build_smtp(core, Inner::default()));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.stream.tls = false;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN");

    // EHLO should advertise AUTH for 10.0.0.1
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("AUTH ")
        .assert_contains(" PLAIN")
        .assert_contains(" LOGIN")
        .assert_not_contains("FUTURERELEASE");

    // Invalid password should be rejected
    session
        .cmd("AUTH PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz", "535 5.7.8")
        .await;

    // Session should be disconnected after second invalid auth attempt
    session
        .ingest(b"AUTH PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz\r\n")
        .await
        .unwrap_err();
    session.response().assert_code("421 4.3.0");

    // Should not be able to send without authenticating
    session.state = State::default();
    session.mail_from("bill@foobar.org", "503 5.5.1").await;

    // Successful PLAIN authentication
    session.data.auth_errors = 0;
    session
        .cmd("AUTH PLAIN AGpvaG4Ac2VjcmV0", "235 2.7.0")
        .await;

    // Users should be able to send emails only from their own email addresses
    session.mail_from("bill@foobar.org", "501 5.5.4").await;
    session.mail_from("john@example.org", "250").await;
    session.data.mail_from.take();

    // Should not be able to authenticate twice
    session
        .cmd("AUTH PLAIN AGpvaG4Ac2VjcmV0", "503 5.5.1")
        .await;

    // FUTURERELEASE extension should be available after authenticating
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("AUTH ")
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN")
        .assert_contains("FUTURERELEASE 86400");

    // Successful LOGIN authentication
    session.data.authenticated_as.clear();
    session.cmd("AUTH LOGIN", "334").await;
    session.cmd("amFuZQ==", "334").await;
    session.cmd("cDRzc3cwcmQ=", "235 2.7.0").await;

    // Login should not be advertised to 10.0.0.2
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.eval_session_params().await;
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("AUTH ")
        .assert_not_contains(" PLAIN")
        .assert_not_contains(" LOGIN");
    session
        .cmd("AUTH PLAIN AGpvaG4Ac2VjcmV0", "503 5.5.1")
        .await;
}
