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

use std::{fs, sync::Arc, time::Duration};

use crate::smtp::{
    inbound::TestQueueEvent, make_temp_dir, session::TestSession, TestConfig, TestSMTP,
};
use smtp::{
    config::AddressMatch,
    core::{Session, SMTP},
};
use utils::config::if_block::IfBlock;

#[tokio::test]
async fn report_analyze() {
    let mut core = SMTP::test();

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_analyze_report_test");
    let report_dir = make_temp_dir("smtp_report_incoming", true);

    let config = &mut core.session.config.rcpt;
    config.relay = IfBlock::new(true);
    let config = &mut core.session.config.data;
    config.max_messages = IfBlock::new(1024);
    let config = &mut core.report.config.analysis;
    config.addresses = vec![
        AddressMatch::StartsWith("reports@".to_string()),
        AddressMatch::EndsWith("@dmarc.foobar.org".to_string()),
        AddressMatch::Equals("feedback@foobar.org".to_string()),
    ];
    config.forward = false;
    config.store = report_dir.temp_dir.clone().into();

    // Create test message
    let core = Arc::new(core);
    let mut session = Session::test(core.clone());
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    let addresses = [
        "reports@foobar.org",
        "rep@dmarc.foobar.org",
        "feedback@foobar.org",
    ];
    let mut ac = 0;
    let mut total_reports_received = 0;
    for (test, num_tests) in [("arf", 5), ("dmarc", 5), ("tls", 2)] {
        for num_test in 1..=num_tests {
            total_reports_received += 1;
            session
                .send_message(
                    "john@test.org",
                    &[addresses[ac % addresses.len()]],
                    &format!("report:{test}{num_test}"),
                    "250",
                )
                .await;
            qr.assert_empty_queue();
            ac += 1;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut total_reports = 0;
    for entry in fs::read_dir(&report_dir.temp_dir).unwrap() {
        let path = entry.unwrap().path();
        assert_ne!(fs::metadata(&path).unwrap().len(), 0);
        total_reports += 1;
    }
    assert_eq!(total_reports, total_reports_received);

    // Test delivery to non-report addresses
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    qr.read_event().await.assert_reload();
    qr.last_queued_message().await;
}
