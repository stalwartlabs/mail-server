/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::Core;

use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS};
use store::Stores;
use utils::config::Config;

use smtp::core::{Inner, Session, State};

use crate::smtp::{
    build_smtp,
    session::{TestSession, VerifyResponse},
    TempDir,
};

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
email = "john@foobar.org"

[[directory."local".principals]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@foobar.org"

[[directory."local".principals]]
name = "bill"
description = "Bill Foobar"
secret = "p4ssw0rd"
email = "bill@foobar.org"

[[directory."local".principals]]
name = "mike"
description = "Mike Foobar"
secret = "p4ssw0rd"
email = "mike@foobar.org"

[session.rcpt]
directory = "'local'"
max-recipients = [{if = "remote_ip = '10.0.0.1'", then = 3},
                {else = 5}]
relay = [{if = "remote_ip = '10.0.0.1'", then = false},
         {else = true}]

[session.rcpt.errors]
total = [{if = "remote_ip = '10.0.0.1'", then = 3},
         {else = 100}]
wait = [{if = "remote_ip = '10.0.0.1'", then = '5ms'},
        {else = '1s'}]

[session.extensions]
dsn = [{if = "remote_ip = '10.0.0.1'", then = false},
       {else = true}]

[[session.throttle]]
match = "remote_ip = '10.0.0.1' && !is_empty(rcpt)"
key = 'sender'
rate = '2/1s'
enable = true

"#;

#[tokio::test]
async fn rcpt() {
    // Enable logging
    crate::enable_logging();

    let tmp_dir = TempDir::new("smtp_rcpt_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;

    // RCPT without MAIL FROM
    let mut session = Session::test(build_smtp(core, Inner::default()));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx1.foobar.org").await;
    session.rcpt_to("jane@foobar.org", "503 5.5.1").await;

    // Relaying is disabled for 10.0.0.1
    session.mail_from("john@example.net", "250").await;
    session.rcpt_to("external@domain.com", "550 5.1.2").await;

    // DSN is disabled for 10.0.0.1
    session
        .ingest(b"RCPT TO:<jane@foobar.org> NOTIFY=SUCCESS,FAILURE,DELAY\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");

    // Send to non-existing user
    session.rcpt_to("tom@foobar.org", "550 5.1.2").await;

    // Exceeding max number of errors
    session
        .ingest(b"RCPT TO:<sam@foobar.org>\r\n")
        .await
        .unwrap_err();
    session.response().assert_code("421 4.3.0");

    // Rate limit
    session.data.rcpt_errors = 0;
    session.state = State::default();
    session.rcpt_to("Jane@FooBar.org", "250").await;
    session.rcpt_to("Bill@FooBar.org", "250").await;
    session.rcpt_to("Mike@FooBar.org", "451 4.4.5").await;

    // Restore rate limit
    tokio::time::sleep(Duration::from_millis(1100)).await;
    session.rcpt_to("Mike@FooBar.org", "250").await;
    session.rcpt_to("john@foobar.org", "451 4.5.3").await;

    // Check recipients
    assert_eq!(session.data.rcpt_to.len(), 3);
    for (rcpt, expected) in
        session
            .data
            .rcpt_to
            .iter()
            .zip(["Jane@FooBar.org", "Bill@FooBar.org", "Mike@FooBar.org"])
    {
        assert_eq!(rcpt.address, expected);
        assert_eq!(rcpt.domain, "foobar.org");
        assert_eq!(rcpt.address_lcase, expected.to_lowercase());
    }

    // Relaying should be allowed for 10.0.0.2
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.eval_session_params().await;
    session.rset().await;
    session.mail_from("john@example.net", "250").await;
    session.rcpt_to("external@domain.com", "250").await;

    // DSN is enabled for 10.0.0.2
    session
        .ingest(b"RCPT TO:<jane@foobar.org> NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;Jane.Doe@Foobar.org\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    let rcpt = session.data.rcpt_to.last().unwrap();
    assert!((rcpt.flags & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE)) != 0);
    assert_eq!(rcpt.dsn_info.as_ref().unwrap(), "Jane.Doe@Foobar.org");
}
