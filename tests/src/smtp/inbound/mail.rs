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
    time::{Duration, Instant, SystemTime},
};

use mail_auth::{common::parse::TxtRecordParser, spf::Spf, IprevResult, SpfResult};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_REQUIRETLS};

use crate::smtp::{
    session::{TestSession, VerifyResponse},
    ParseTestConfig, TestConfig,
};
use smtp::{
    config::{ConfigContext, IfBlock, VerifyStrategy},
    core::{Session, SMTP},
};

#[tokio::test]
async fn mail() {
    let mut core = SMTP::test();
    core.resolvers.dns.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ptr_add(
        "10.0.0.1".parse().unwrap(),
        vec!["mx1.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ipv4_add(
        "mx1.foobar.org.",
        vec!["10.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );
    core.resolvers.dns.ptr_add(
        "10.0.0.2".parse().unwrap(),
        vec!["mx2.foobar.org.".to_string()],
        Instant::now() + Duration::from_secs(5),
    );

    let mut config = &mut core.session.config;
    config.ehlo.require = IfBlock::new(true);
    core.mail_auth.spf.verify_ehlo = IfBlock::new(VerifyStrategy::Relaxed);
    core.mail_auth.spf.verify_mail_from = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::new(&[]));
    core.mail_auth.iprev.verify = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'strict'},
    {else = 'relaxed'}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.future_release = r"[{if = 'remote-ip', eq = '10.0.0.2', then = '1d'},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.deliver_by = r"[{if = 'remote-ip', eq = '10.0.0.2', then = '1d'},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.requiretls = r"[{if = 'remote-ip', eq = '10.0.0.2', then = true},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.extensions.mt_priority = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 'nsep'},
    {else = false}]"
        .parse_if(&ConfigContext::new(&[]));
    config.data.max_message_size = r"[{if = 'remote-ip', eq = '10.0.0.2', then = 2048},
    {else = 1024}]"
        .parse_if(&ConfigContext::new(&[]));

    config.throttle.mail_from = r"[[throttle]]
    match = {if = 'remote-ip', eq = '10.0.0.1'}
    key = 'sender'
    rate = '2/1s'
    "
    .parse_throttle(&ConfigContext::new(&[]));

    // Be rude and do not say EHLO
    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Both IPREV and SPF should pass
    session.ingest(b"EHLO mx1.foobar.org\r\n").await.unwrap();
    session.response().assert_code("250");
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(
        session.data.spf_ehlo.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.spf_mail_from.as_ref().unwrap().result(),
        SpfResult::Pass
    );
    assert_eq!(
        session.data.iprev.as_ref().unwrap().result(),
        &IprevResult::Pass
    );

    // Multiple MAIL FROMs should not be allowed
    session
        .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("503 5.5.1");

    // Test rate limit
    for n in 0..2 {
        session.rset().await;
        session
            .ingest(b"MAIL FROM:<bill@foobar.org>\r\n")
            .await
            .unwrap();
        session
            .response()
            .assert_code(if n == 0 { "250" } else { "451 4.4.5" });
    }

    // Test disabled extensions
    for param in [
        "HOLDFOR=123",
        "HOLDUNTIL=49374347",
        "MT-PRIORITY=3",
        "BY=120;R",
        "REQUIRETLS",
    ] {
        session
            .ingest(format!("MAIL FROM:<params@foobar.org> {param}\r\n").as_bytes())
            .await
            .unwrap();
        session.response().assert_code("501 5.5.4");
    }

    // Test size with a large value
    session
        .ingest(b"MAIL FROM:<bill@foobar.org> SIZE=1512\r\n")
        .await
        .unwrap();
    session.response().assert_code("552 5.3.4");

    // Test strict IPREV
    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.data.iprev = None;
    session.eval_session_params().await;
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.25");
    session.data.iprev = None;
    core.resolvers.dns.ipv4_add(
        "mx2.foobar.org.",
        vec!["10.0.0.2".parse().unwrap()],
        Instant::now() + Duration::from_secs(5),
    );

    // Test strict SPF
    session
        .ingest(b"MAIL FROM:<jane@foobar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("550 5.7.23");
    core.resolvers.dns.txt_add(
        "foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    session
        .ingest(b"MAIL FROM:<Jane@FooBar.org>\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    let mail_from = session.data.mail_from.as_ref().unwrap();
    assert_eq!(mail_from.domain, "foobar.org");
    assert_eq!(mail_from.address, "Jane@FooBar.org");
    assert_eq!(mail_from.address_lcase, "jane@foobar.org");
    session.rset().await;

    // Test SIZE extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> SIZE=1023\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    session.rset().await;

    // Test MT-PRIORITY extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> MT-PRIORITY=-3\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.priority, -3);
    session.rset().await;

    // Test REQUIRETLS extension
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> REQUIRETLS\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_REQUIRETLS) != 0);
    session.rset().await;

    // Test DELIVERBY extension with by-mode=R
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=120;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_BY_RETURN) != 0);
    assert_eq!(session.data.delivery_by, 120);
    session.rset().await;

    // Test DELIVERBY extension with by-mode=N
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=-456;N\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert!((session.data.mail_from.as_ref().unwrap().flags & MAIL_BY_NOTIFY) != 0);
    assert_eq!(session.data.delivery_by, -456);
    session.rset().await;

    // Test DELIVERBY extension with invalid by-mode=R
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=-1;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    session
        .ingest(b"MAIL FROM:<jane@foobar.org> BY=99999;R\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    // Test FUTURERELEASE extension with HOLDFOR
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> HOLDFOR=1234\r\n")
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.future_release, 1234);
    session.rset().await;

    // Test FUTURERELEASE extension with invalid HOLDFOR falue
    session
        .ingest(b"MAIL FROM:<jane@foobar.org> HOLDFOR=99999\r\n")
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;

    // Test FUTURERELEASE extension with HOLDUNTIL
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    session
        .ingest(format!("MAIL FROM:<jane@foobar.org> HOLDUNTIL={}\r\n", now + 10).as_bytes())
        .await
        .unwrap();
    session.response().assert_code("250");
    assert_eq!(session.data.future_release, 10);
    session.rset().await;

    // Test FUTURERELEASE extension with invalud HOLDUNTIL value
    session
        .ingest(format!("MAIL FROM:<jane@foobar.org> HOLDUNTIL={}\r\n", now + 99999).as_bytes())
        .await
        .unwrap();
    session.response().assert_code("501 5.5.4");
    session.rset().await;
}
