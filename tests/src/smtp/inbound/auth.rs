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

use directory::config::ConfigDirectory;
use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN};
use utils::config::Config;

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::ConfigContext,
    core::{Session, State, SMTP},
};

const DIRECTORY: &str = r#"
[directory."local"]
type = "memory"

[[directory."local".users]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["john@example.org", "jdoe@example.org", "john.doe@example.org"]
email-list = ["info@example.org"]
member-of = ["sales"]

[[directory."local".users]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@example.org"
email-list = ["info@example.org"]
member-of = ["sales", "support"]
"#;

#[tokio::test]
async fn auth() {
    let mut core = SMTP::test();
    let mut ctx = ConfigContext::new(&[]);
    ctx.directory = Config::parse(DIRECTORY).unwrap().parse_directory().unwrap();

    let mut config = &mut core.session.config.auth;

    config.require = r"[{if = 'remote-ip', eq = '10.0.0.1', then = true},
    {else = false}]"
        .parse_if(&ctx);
    config.directory = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'local'},
    {else = false}]"
        .parse_if::<Option<String>>(&ctx)
        .map_if_block(&ctx.directory.directories, "", "")
        .unwrap();
    config.errors_max = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 2},
    {else = 3}]"
        .parse_if(&ctx);
    config.errors_wait = "'100ms'".parse_if(&ctx);
    config.mechanisms = format!(
        "[{{if = 'remote-ip', eq = '10.0.0.1', then = {}}},
    {{else = 0}}]",
        AUTH_PLAIN | AUTH_LOGIN
    )
    .as_str()
    .parse_if(&ctx);
    core.session.config.extensions.future_release =
        r"[{if = 'authenticated-as', ne = '', then = '1d'},
    {else = false}]"
            .parse_if(&ConfigContext::new(&[]));

    // EHLO should not avertise plain text auth without TLS
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
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
    session.mail_from("bill@foobar.org", "250").await;
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
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
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
