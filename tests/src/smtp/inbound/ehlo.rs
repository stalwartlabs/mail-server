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

use std::time::{Duration, Instant};

use mail_auth::{common::parse::TxtRecordParser, spf::Spf, SpfResult};

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::{ConfigContext, IfBlock},
    core::{Session, SMTP},
};

#[tokio::test]
async fn ehlo() {
    let mut core = SMTP::test();
    core.resolvers.dns.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "mx2.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    let config = &mut core.session.config;
    config.data.max_message_size = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 1024},
    {else = 2048}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.future_release = r"[{if = 'remote-ip', eq = '10.0.0.1', then = '1h'},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.mt_priority = r"[{if = 'remote-ip', eq = '10.0.0.1', then = 'nsep'},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    core.mail_auth.spf.verify_ehlo = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::new(&[]));
    config.ehlo.reject_non_fqdn = IfBlock::new(true);

    // Reject non-FQDN domains
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.stream.tls = false;
    session.eval_session_params().await;
    session.cmd("EHLO domain", "550 5.5.0").await;

    // EHLO capabilities evaluation
    session
        .cmd("EHLO mx1.foobar.org", "250")
        .await
        .assert_contains("SIZE 1024")
        .assert_contains("MT-PRIORITY NSEP")
        .assert_contains("FUTURERELEASE 3600")
        .assert_contains("STARTTLS");

    // SPF should be a Pass for 10.0.0.1
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );

    // Test SPF strict mode
    session.data.helo_domain = String::new();
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.stream.tls = true;
    session.eval_session_params().await;
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("550 5.7.23");

    // EHLO capabilities evaluation
    session.ingest(b"EHLO mx2.foobar.org\r\n").await.unwrap();
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    session
        .response()
        .assert_code("250")
        .assert_contains("SIZE 2048")
        .assert_not_contains("MT-PRIORITY")
        .assert_not_contains("FUTURERELEASE")
        .assert_not_contains("STARTTLS");
}
