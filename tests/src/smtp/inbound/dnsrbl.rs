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

use std::time::{Duration, Instant};

use smtp::{
    config::IfBlock,
    core::{Core, Session},
};

use crate::smtp::{inbound::TestQueueEvent, session::TestSession, TestConfig, TestCore};

#[tokio::test]
async fn dnsrbl() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    let mut core = Core::test();
    for entry in [
        "1.0.0.10.zen.spamhaus.org",
        "2.0.0.10.b.barracudacentral.org",
        "spammer.com.dbl.spamhaus.org",
        "spammer.net.dbl.spamhaus.org",
        "spammer.org.dbl.spamhaus.org",
    ] {
        core.resolvers.dns.ipv4_add(
            entry,
            vec!["127.0.0.2".parse().unwrap()],
            Instant::now() + Duration::from_secs(10),
        );
    }
    core.resolvers.dns.ipv4_add(
        "shouldwork.org.dbl.spamhaus.org",
        vec!["127.255.255.254".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ptr_add(
        "10.0.0.3".parse().unwrap(),
        vec!["spammer.org.".to_string()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut qr = core.init_test_queue("smtp_dnsrbl_test");
    let mut config = &mut core.mail_auth.dnsbl;
    config.ip_lookup = vec![
        "zen.spamhaus.org".to_string(),
        "bl.spamcop.net".to_string(),
        "b.barracudacentral.org".to_string(),
    ];
    config.domain_lookup = vec!["dbl.spamhaus.org".to_string()];
    config.verify = IfBlock::new(u32::MAX);
    core.session.config.rcpt.relay = IfBlock::new(true);

    // DNSRBL codes other than 127.0.0.0/8 should not be interpreted as block
    let mut session = Session::test(core);
    session.data.remote_ip = "10.0.0.4".parse().unwrap();
    session.eval_session_params().await;
    session.cmd("EHLO shouldwork.org", "250").await;

    // Reject blocked EHLO domains
    session
        .cmd(
            "EHLO spammer.com",
            "554 5.7.1 Service unavailable; Domain 'spammer.com' blocked",
        )
        .await;

    // Reject blocked return paths
    session.ehlo("foobar.org").await;
    session
        .mail_from(
            "list@spammer.com",
            "554 5.7.1 Service unavailable; Domain 'spammer.com' blocked",
        )
        .await;

    // Reject blocked From addresses
    session
        .send_message(
            "bill@foobar.org",
            &["jane@example.org"],
            concat!(
                "From: Mr. Spammer <mr@spammer.net>\r\n",
                "To: jane@example.org\r\n",
                "Subject: Adwords is expensive, please let me spam you.\r\n\r\n",
                "Buy my spammer product\r\n"
            ),
            "554 5.7.1 Service unavailable; Domain 'spammer.net' blocked",
        )
        .await;

    // Reject blocked IPs
    session.data.remote_ip = "10.0.0.1".parse().unwrap();
    session.data.iprev.take();
    session.reset_dnsbl_error();
    session.verify_ip_dnsbl().await;
    session.ehlo("foobar.org").await;
    session
        .mail_from(
            "bill@foobar.org",
            "554 5.7.1 Service unavailable; IP address 10.0.0.1 blocked",
        )
        .await;

    session.data.remote_ip = "10.0.0.2".parse().unwrap();
    session.data.iprev.take();
    session.reset_dnsbl_error();
    session.verify_ip_dnsbl().await;
    session.ehlo("foobar.org").await;
    session
        .mail_from(
            "bill@foobar.org",
            "554 5.7.1 Service unavailable; IP address 10.0.0.2 blocked",
        )
        .await;

    // Reject blocked PTR domains
    session.data.remote_ip = "10.0.0.3".parse().unwrap();
    session.data.iprev.take();
    session.reset_dnsbl_error();
    session.verify_ip_dnsbl().await;
    session.ehlo("foobar.org").await;
    session
        .mail_from(
            "bill@foobar.org",
            "554 5.7.1 Service unavailable; Domain 'spammer.org.' blocked",
        )
        .await;

    // Non-blocked IPs should work
    session.data.remote_ip = "10.0.0.4".parse().unwrap();
    session.data.iprev.take();
    session.reset_dnsbl_error();
    session.verify_ip_dnsbl().await;
    session.ehlo("foobar.org").await;
    session
        .send_message("bill@foobar.org", &["jane@example.org"], "test:dkim", "250")
        .await;
    qr.read_event().await.unwrap_message();
}
