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

use directory::core::config::ConfigDirectory;
use store::{Store, Stores};
use utils::config::{if_block::IfBlock, Config, Servers};

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::ConfigContext,
    core::{Session, SMTP},
};

const DIRECTORY: &str = r#"
[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["john@foobar.org"]
email-list = ["sales@foobar.org"]

[[directory."local".principals]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@foobar.org"
email-list = ["sales@foobar.org"]

[[directory."local".principals]]
name = "bill"
description = "Bill Foobar"
secret = "p4ssw0rd"
email = "bill@foobar.org"
email-list = ["sales@foobar.org"]

"#;

#[tokio::test]
async fn vrfy_expn() {
    let mut core = SMTP::test();
    let ctx = ConfigContext::new(&[]);

    let directory = Config::new(DIRECTORY)
        .unwrap()
        .parse_directory(&Stores::default(), &Servers::default(), Store::default())
        .await
        .unwrap();
    let config = &mut core.session.config.rcpt;
    config.directory = IfBlock::new("local".to_string());

    let config = &mut core.session.config.extensions;
    config.vrfy = r"[{if = 'remote-ip', eq = '10.0.0.1', then = true},
    {else = false}]"
        .parse_if();
    config.expn = r"[{if = 'remote-ip', eq = '10.0.0.1', then = true},
    {else = false}]"
        .parse_if();

    // EHLO should not avertise VRFY/EXPN to 10.0.0.2
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("EXPN")
        .assert_not_contains("VRFY");
    session.cmd("VRFY john", "252 2.5.1").await;
    session.cmd("EXPN sales@foobar.org", "252 2.5.1").await;

    // EHLO should advertise VRFY/EXPN for 10.0.0.1
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("EXPN")
        .assert_contains("VRFY");

    // Successful VRFY
    session.cmd("VRFY john", "250 john@foobar.org").await;

    // Successful EXPN
    session
        .cmd("EXPN sales@foobar.org", "250")
        .await
        .assert_contains("250-john@foobar.org")
        .assert_contains("250-jane@foobar.org")
        .assert_contains("250 bill@foobar.org");

    // Non-existent VRFY
    session.cmd("VRFY robert", "550 5.1.2").await;

    // Non-existent EXPN
    session.cmd("EXPN procurement", "550 5.1.2").await;
}
