/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::smtp::{inbound::TestQueueEvent, outbound::TestServer, session::TestSession};

use store::{
    write::{ReportClass, ValueClass},
    IterateParams, ValueKey,
};

const CONFIG: &str = r#"
[session.rcpt]
relay = true

[session.data.limits]
messages = 100

[report.analysis]
addresses = ["reports@*", "*@dmarc.foobar.org", "feedback@foobar.org"]
forward = false
store = "1s"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn report_analyze() {
        // Enable logging
        crate::enable_logging();

    // Create temp dir for queue
    let mut local = TestServer::new("smtp_analyze_report_test", CONFIG, true).await;

    // Create test message
    let mut session = local.new_session();
    let qr = &mut local.qr;
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
            qr.assert_no_events();
            ac += 1;
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    //let c = tokio::time::sleep(Duration::from_secs(86400)).await;

    // Purging the database shouldn't remove the reports
    qr.store.purge_store().await.unwrap();

    // Make sure the reports are in the store
    let mut total_reports = 0;
    qr.store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
                ValueKey::from(ValueClass::Report(ReportClass::Arf {
                    id: u64::MAX,
                    expires: u64::MAX,
                })),
            ),
            |_, _| {
                total_reports += 1;
                Ok(true)
            },
        )
        .await
        .unwrap();
    assert_eq!(total_reports, total_reports_received);

    // Wait one second, purge, and make sure they are gone
    tokio::time::sleep(Duration::from_secs(1)).await;
    qr.store.purge_store().await.unwrap();
    let mut total_reports = 0;
    qr.store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
                ValueKey::from(ValueClass::Report(ReportClass::Arf {
                    id: u64::MAX,
                    expires: u64::MAX,
                })),
            ),
            |_, _| {
                total_reports += 1;
                Ok(true)
            },
        )
        .await
        .unwrap();
    assert_eq!(total_reports, 0);

    // Test delivery to non-report addresses
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    qr.read_event().await.assert_reload();
    qr.last_queued_message().await;
}
