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

use std::time::Duration;

use directory::config::ConfigDirectory;
use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS};
use store::Stores;
use utils::config::Config;

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::{ConfigContext, IfBlock, MaybeDynValue},
    core::{Session, State, SMTP},
};

const DIRECTORY: &str = r#"
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

"#;

#[tokio::test]
async fn rcpt() {
    let mut core = SMTP::test();

    let config_ext = &mut core.session.config.extensions;
    let directory = Config::new(DIRECTORY)
        .unwrap()
        .parse_directory(&Stores::default(), None)
        .unwrap();
    let config = &mut core.session.config.rcpt;
    config.directory = IfBlock::new(Some(MaybeDynValue::Static(
        directory.directories.get("local").unwrap().clone(),
    )));
    config.max_recipients = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 3},
    {else = 5}]"
        .parse_if(&ConfigContext::new(&[]));
    config.relay = r"[{if = 'remote-ip', eq = '10.0.0.1', then = false},
    {else = true}]"
        .parse_if(&ConfigContext::new(&[]));
    config_ext.dsn = r"[{if = 'remote-ip', eq = '10.0.0.1', then = false},
    {else = true}]"
        .parse_if(&ConfigContext::new(&[]));
    config.errors_max = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 3},
    {else = 100}]"
        .parse_if(&ConfigContext::new(&[]));
    config.errors_wait = r"[{if = 'remote-ip', eq = '10.0.0.1', then = '5ms'},
    {else = '1s'}]"
        .parse_if(&ConfigContext::new(&[]));
    core.session.config.throttle.rcpt_to = r"[[throttle]]
    match = {if = 'remote-ip', eq = '10.0.0.1'}
    key = 'sender'
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::new(&[]));

    // RCPT without MAIL FROM
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
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
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
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
