/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{io::Read, sync::Arc, time::Duration};

use common::config::smtp::report::AggregateFrequency;
use mail_auth::{
    common::parse::TxtRecordParser,
    flate2::read::GzDecoder,
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, PolicyType, ResultType, TlsReport},
};
use store::write::QueueClass;

use smtp::reporting::{tls::TLS_HTTP_REPORT, TlsEvent};

use crate::smtp::{
    inbound::{sign::SIGNATURES, TestMessage},
    outbound::TestServer,
    session::VerifyResponse,
};

const CONFIG: &str = r#"
[session.rcpt]
relay = true

[report]
submitter = "'mx.example.org'"

[report.tls.aggregate]
from-name = "'Report Subsystem'"
from-address = "'reports@example.org'"
org-name = "'Foobar, Inc.'"
contact-info = "'https://foobar.org/contact'"
send = "daily"
max-size = 1532
sign = "['rsa']"
"#;

#[tokio::test]
async fn report_tls() {
    // Enable logging
    crate::enable_logging();

    // Create scheduler
    let mut local = TestServer::new(
        "smtp_report_tls_test",
        CONFIG.to_string() + SIGNATURES,
        true,
    )
    .await;
    let core = local.build_smtp();
    let qr = &mut local.qr;

    // Schedule TLS reports to be delivered via email
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap());

    for _ in 0..2 {
        // Add two successful records
        core.schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: smtp::reporting::PolicyType::None,
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
        }))
        .await;
    }

    for (policy, rt) in [
        (
            smtp::reporting::PolicyType::None, // Quota limited at 1532 bytes, this should not be included in the report.
            ResultType::CertificateExpired,
        ),
        (
            smtp::reporting::PolicyType::Tlsa(None),
            ResultType::TlsaInvalid,
        ),
        (
            smtp::reporting::PolicyType::Sts(None),
            ResultType::StsPolicyFetchError,
        ),
        (
            smtp::reporting::PolicyType::Sts(None),
            ResultType::StsPolicyInvalid,
        ),
        (
            smtp::reporting::PolicyType::Sts(None),
            ResultType::StsWebpkiInvalid,
        ),
    ] {
        core.schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy,
            failure: FailureDetails::new(rt).into(),
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
        }))
        .await;
    }

    // Wait for flush
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reports = qr.read_report_events().await;
    assert_eq!(reports.len(), 3);
    let mut tls_reports = Vec::with_capacity(3);
    for report in reports {
        match report {
            QueueClass::TlsReportHeader(event) => {
                tls_reports.push(event);
            }
            _ => unreachable!(),
        }
    }
    core.send_tls_aggregate_report(tls_reports).await;

    // Expect report
    let message = qr.expect_message().await;
    assert_eq!(
        message.recipients.last().unwrap().address,
        "reports@foobar.org"
    );
    assert_eq!(message.return_path, "reports@example.org");
    message
        .read_lines(qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: <reports@foobar.org>")
        .assert_contains("Report Domain: foobar.org")
        .assert_contains("Submitter: mx.example.org");

    // Verify generated report
    let report = TlsReport::parse_rfc5322(message.read_message(qr).await.as_bytes()).unwrap();
    assert_eq!(report.organization_name.unwrap(), "Foobar, Inc.");
    assert_eq!(report.contact_info.unwrap(), "https://foobar.org/contact");
    assert_eq!(report.policies.len(), 3);
    let mut seen = [false; 3];
    for policy in report.policies {
        match policy.policy.policy_type {
            PolicyType::Tlsa => {
                seen[0] = true;
                assert_eq!(policy.summary.total_failure, 1);
                assert_eq!(policy.summary.total_success, 0);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 1);
                assert_eq!(
                    policy.failure_details.first().unwrap().result_type,
                    ResultType::TlsaInvalid
                );
            }
            PolicyType::Sts => {
                seen[1] = true;
                assert_eq!(policy.summary.total_failure, 2);
                assert_eq!(policy.summary.total_success, 0);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 2);
                assert!(policy
                    .failure_details
                    .iter()
                    .any(|d| d.result_type == ResultType::StsPolicyFetchError));
                assert!(policy
                    .failure_details
                    .iter()
                    .any(|d| d.result_type == ResultType::StsPolicyInvalid));
            }
            PolicyType::NoPolicyFound => {
                seen[2] = true;
                assert_eq!(policy.summary.total_failure, 1);
                assert_eq!(policy.summary.total_success, 2);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 1);
                /*assert_eq!(
                    policy.failure_details.first().unwrap().result_type,
                    ResultType::CertificateExpired
                );*/
            }
            PolicyType::Other => unreachable!(),
        }
    }

    assert!(seen[0]);
    assert!(seen[1]);
    assert!(seen[2]);

    // Schedule TLS reports to be delivered via https
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=https://127.0.0.1/tls").unwrap());

    for _ in 0..2 {
        // Add two successful records
        core.schedule_tls(Box::new(TlsEvent {
            domain: "foobar.org".to_string(),
            policy: smtp::reporting::PolicyType::None,
            failure: None,
            tls_record: tls_record.clone(),
            interval: AggregateFrequency::Daily,
        }))
        .await;
    }

    let reports = qr.read_report_events().await;
    assert_eq!(reports.len(), 1);
    match reports.into_iter().next().unwrap() {
        QueueClass::TlsReportHeader(event) => {
            core.send_tls_aggregate_report(vec![event]).await;
        }
        _ => unreachable!(),
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Uncompress report
    {
        let gz_report = TLS_HTTP_REPORT.lock();
        let mut file = GzDecoder::new(&gz_report[..]);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let report = TlsReport::parse_json(&buf).unwrap();
        assert_eq!(report.organization_name.unwrap(), "Foobar, Inc.");
        assert_eq!(report.contact_info.unwrap(), "https://foobar.org/contact");
        assert_eq!(report.policies.len(), 1);
    }
    qr.assert_report_is_empty().await;
}
