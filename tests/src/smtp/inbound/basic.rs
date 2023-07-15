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

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    TestConfig,
};
use smtp::core::{Session, SMTP};

#[tokio::test]
async fn basic_commands() {
    let mut session = Session::test(SMTP::test());

    // STARTTLS should be available on clear text connections
    session.stream.tls = false;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("STARTTLS");
    assert!(!session.ingest(b"STARTTLS\r\n").await.unwrap());
    session.response().assert_contains("220 2.0.0");

    // STARTTLS should not be offered on TLS connections
    session.stream.tls = true;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("STARTTLS");
    session.cmd("STARTTLS", "504 5.7.4").await;

    // Test NOOP
    session.cmd("NOOP", "250").await;

    // Test RSET
    session.cmd("RSET", "250").await;

    // Test HELP
    session.cmd("HELP QUIT", "250").await;

    // Test LHLO on SMTP channel
    session.cmd("LHLO domain.org", "502").await;

    // Test QUIT
    session.ingest(b"QUIT\r\n").await.unwrap_err();
    session.response().assert_code("221");
}
