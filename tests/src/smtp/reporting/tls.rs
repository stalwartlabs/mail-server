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

use std::{io::Read, sync::Arc, time::Duration};

use common::{config::smtp::report::AggregateFrequency, expr::if_block::IfBlock};
use mail_auth::{
    common::parse::TxtRecordParser,
    flate2::read::GzDecoder,
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, PolicyType, ResultType, TlsReport},
};
use store::write::QueueClass;

use crate::smtp::{
    inbound::{sign::TextConfigContext, TestMessage},
    session::VerifyResponse,
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    core::SMTP,
    reporting::{tls::TLS_HTTP_REPORT, TlsEvent},
};

#[tokio::test]
async fn report_tls() {
    /*let disable = "true";
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Create scheduler
    let mut core = SMTP::test();
    core.core.storage.signers = ConfigContext::new().parse_signatures().signers;
    let config = &mut core.core.smtp.report;
    config.tls.sign = "\"['rsa']\"".parse_if();
    config.tls.max_size = IfBlock::new(1532);
    config.submitter = IfBlock::new("mx.example.org".to_string());
    config.tls.address = IfBlock::new("reports@example.org".to_string());
    config.tls.org_name = IfBlock::new("Foobar, Inc.".to_string());
    config.tls.contact_info = IfBlock::new("https://foobar.org/contact".to_string());

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_report_tls_test");
    let core = Arc::new(core);

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
        .read_lines(&qr)
        .await
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: <reports@foobar.org>")
        .assert_contains("Report Domain: foobar.org")
        .assert_contains("Submitter: mx.example.org");

    // Verify generated report
    let report = TlsReport::parse_rfc5322(message.read_message(&qr).await.as_bytes()).unwrap();
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
                assert_eq!(policy.summary.total_failure, 3);
                assert_eq!(policy.summary.total_success, 0);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 3);
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
                assert_eq!(policy.summary.total_failure, 0);
                assert_eq!(policy.summary.total_success, 2);
                assert_eq!(policy.policy.policy_domain, "foobar.org");
                assert_eq!(policy.failure_details.len(), 0);
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
