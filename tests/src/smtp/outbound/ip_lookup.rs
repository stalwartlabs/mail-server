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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{IpLookupStrategy, MX};
use utils::config::{if_block::IfBlock, ServerProtocol};

use crate::smtp::{outbound::start_test_server, session::TestSession, TestConfig, TestSMTP};
use smtp::core::{Session, SMTP};

#[tokio::test]
#[serial_test::serial]
async fn ip_lookup_strategy() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Start test server
    let mut core = SMTP::test();
    core.session.config.rcpt.relay = IfBlock::new(true);
    let mut remote_qr = core.init_test_queue("smtp_iplookup_remote");
    let _rx = start_test_server(core.into(), &[ServerProtocol::Smtp]);

    for strategy in [IpLookupStrategy::Ipv6Only, IpLookupStrategy::Ipv6thenIpv4] {
        //println!("-> Strategy: {:?}", strategy);
        // Add mock DNS entries
        let mut core = SMTP::test();
        core.queue.config.ip_strategy = IfBlock::new(IpLookupStrategy::Ipv6thenIpv4);
        core.resolvers.dns.mx_add(
            "foobar.org",
            vec![MX {
                exchanges: vec!["mx.foobar.org".to_string()],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(10),
        );
        if matches!(strategy, IpLookupStrategy::Ipv6thenIpv4) {
            core.resolvers.dns.ipv4_add(
                "mx.foobar.org",
                vec!["127.0.0.1".parse().unwrap()],
                Instant::now() + Duration::from_secs(10),
            );
        }
        core.resolvers.dns.ipv6_add(
            "mx.foobar.org",
            vec!["::1".parse().unwrap()],
            Instant::now() + Duration::from_secs(10),
        );

        // Retry on failed STARTTLS
        let mut local_qr = core.init_test_queue("smtp_iplookup_local");
        core.session.config.rcpt.relay = IfBlock::new(true);

        let core = Arc::new(core);
        let mut session = Session::test(core.clone());
        session.data.remote_ip_str = "10.0.0.1".to_string();
        session.eval_session_params().await;
        session.ehlo("mx.test.org").await;
        session
            .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
            .await;
        local_qr
            .expect_message_then_deliver()
            .await
            .try_deliver(core.clone())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if matches!(strategy, IpLookupStrategy::Ipv6thenIpv4) {
            remote_qr.expect_message().await;
        } else {
            let message = local_qr.last_queued_message().await;
            let status = message.domains[0].status.to_string();
            assert!(
                status.contains("Connection refused"),
                "Message: {:?}",
                message
            );
        }
    }
}
