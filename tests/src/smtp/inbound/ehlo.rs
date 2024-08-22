/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::Core;
use mail_auth::{common::parse::TxtRecordParser, spf::Spf, SpfResult};

use smtp::core::{Inner, Session};
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    session::{TestSession, VerifyResponse},
};

const CONFIG: &str = r#"
[session.data.limits]
size = [{if = "remote_ip = '10.0.0.1'", then = 1024},
        {else = 2048}]

[session.extensions]
future-release = [{if = "remote_ip = '10.0.0.1'", then = '1h'},
                  {else = false}]
mt-priority = [{if = "remote_ip = '10.0.0.1'", then = 'nsep'},
               {else = false}]

[session.ehlo]
reject-non-fqdn = true

[auth.spf.verify]
ehlo = [{if = "remote_ip = '10.0.0.2'", then = 'strict'},
        {else = 'relaxed'}]
"#;

#[tokio::test]
async fn ehlo() {
        // Enable logging
        crate::enable_logging();

    let mut config = Config::new(CONFIG).unwrap();
    let core = Core::parse(&mut config, Default::default(), Default::default()).await;
    core.smtp.resolvers.dns.txt_add(
        "mx1.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.1 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );
    core.smtp.resolvers.dns.txt_add(
        "mx2.foobar.org",
        Spf::parse(b"v=spf1 ip4:10.0.0.2 -all").unwrap(),
        Instant::now() + Duration::from_secs(5),
    );

    // Reject non-FQDN domains
    let mut session = Session::test(build_smtp(core, Inner::default()));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
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
    session.data.remote_ip_str = "10.0.0.2".to_string();
    session.data.remote_ip = session.data.remote_ip_str.parse().unwrap();
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
