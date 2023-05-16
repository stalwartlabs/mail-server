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

use std::{sync::Arc, time::Duration};

use ahash::AHashSet;
use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS};

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::{ConfigContext, IfBlock},
    core::{Core, Session, State},
    lookup::Lookup,
};

#[tokio::test]
async fn rcpt() {
    let mut core = Core::test();

    let list_addresses = Lookup::Local(AHashSet::from_iter([
        "jane@foobar.org".to_string(),
        "bill@foobar.org".to_string(),
        "mike@foobar.org".to_string(),
        "john@foobar.org".to_string(),
    ]));
    let list_domains = Lookup::Local(AHashSet::from_iter(["foobar.org".to_string()]));

    let mut config = &mut core.session.config.rcpt;
    let mut config_ext = &mut core.session.config.extensions;
    config.lookup_domains = IfBlock::new(Some(Arc::new(list_domains)));
    config.lookup_addresses = IfBlock::new(Some(Arc::new(list_addresses)));
    config.max_recipients = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 3},
    {else = 5}]"
        .parse_if(&ConfigContext::default());
    config.relay = r"[{if = 'remote-ip', eq = '10.0.0.1', then = false},
    {else = true}]"
        .parse_if(&ConfigContext::default());
    config_ext.dsn = r"[{if = 'remote-ip', eq = '10.0.0.1', then = false},
    {else = true}]"
        .parse_if(&ConfigContext::default());
    config.errors_max = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 3},
    {else = 100}]"
        .parse_if(&ConfigContext::default());
    config.errors_wait = r"[{if = 'remote-ip', eq = '10.0.0.1', then = '5ms'},
    {else = '1s'}]"
        .parse_if(&ConfigContext::default());
    core.session.config.throttle.rcpt_to = r"[[throttle]]
    match = {if = 'remote-ip', eq = '10.0.0.1'}
    key = 'sender'
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::default());

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
