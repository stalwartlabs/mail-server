/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::config::smtp::report::AggregateFrequency;
use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::{Dmarc, URI},
    mta_sts::TlsRpt,
    report::{ActionDisposition, Alignment, Disposition, DmarcResult, PolicyPublished, Record},
};
use store::write::QueueClass;

use crate::smtp::outbound::TestServer;
use smtp::reporting::{dmarc::DmarcFormat, DmarcEvent, PolicyType, TlsEvent};

const CONFIG: &str = r#"
[session.rcpt]
relay = true

[report.dmarc.aggregate]
max-size = 500
send = "daily"

[report.tls.aggregate]
max-size = 550
send = "daily"
"#;

#[tokio::test]
async fn report_scheduler() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Create scheduler
    let local = TestServer::new("smtp_report_queue_test", CONFIG, true).await;
    let core = local.build_smtp();
    let qr = &local.qr;

    // Schedule two events with a same policy and another one with a different policy
    let dmarc_record =
        Arc::new(Dmarc::parse(b"v=DMARC1; p=quarantine; rua=mailto:dmarc@foobar.org").unwrap());
    core.schedule_dmarc(Box::new(DmarcEvent {
        domain: "foobar.org".to_string(),
        report_record: Record::new()
            .with_source_ip("192.168.1.2".parse().unwrap())
            .with_action_disposition(ActionDisposition::Pass)
            .with_dmarc_dkim_result(DmarcResult::Pass)
            .with_dmarc_spf_result(DmarcResult::Fail)
            .with_envelope_from("hello@example.org")
            .with_envelope_to("other@example.org")
            .with_header_from("bye@example.org"),
        dmarc_record: dmarc_record.clone(),
        interval: AggregateFrequency::Weekly,
    }))
    .await;

    // No records should be added once the 550 bytes max size is reached
    for _ in 0..10 {
        core.schedule_dmarc(Box::new(DmarcEvent {
            domain: "foobar.org".to_string(),
            report_record: Record::new()
                .with_source_ip("192.168.1.2".parse().unwrap())
                .with_action_disposition(ActionDisposition::Pass)
                .with_dmarc_dkim_result(DmarcResult::Pass)
                .with_dmarc_spf_result(DmarcResult::Fail)
                .with_envelope_from("hello@example.org")
                .with_envelope_to("other@example.org")
                .with_header_from("bye@example.org"),
            dmarc_record: dmarc_record.clone(),
            interval: AggregateFrequency::Weekly,
        }))
        .await;
    }
    let dmarc_record =
        Arc::new(Dmarc::parse(b"v=DMARC1; p=reject; rua=mailto:dmarc@foobar.org").unwrap());
    core.schedule_dmarc(Box::new(DmarcEvent {
        domain: "foobar.org".to_string(),
        report_record: Record::new()
            .with_source_ip("a:b:c::e:f".parse().unwrap())
            .with_action_disposition(ActionDisposition::Reject)
            .with_dmarc_dkim_result(DmarcResult::Fail)
            .with_dmarc_spf_result(DmarcResult::Pass),
        dmarc_record: dmarc_record.clone(),
        interval: AggregateFrequency::Weekly,
    }))
    .await;

    // Schedule TLS event
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap());
    core.schedule_tls(Box::new(TlsEvent {
        domain: "foobar.org".to_string(),
        policy: PolicyType::Tlsa(None),
        failure: None,
        tls_record: tls_record.clone(),
        interval: AggregateFrequency::Daily,
    }))
    .await;
    core.schedule_tls(Box::new(TlsEvent {
        domain: "foobar.org".to_string(),
        policy: PolicyType::Tlsa(None),
        failure: None,
        tls_record: tls_record.clone(),
        interval: AggregateFrequency::Daily,
    }))
    .await;
    core.schedule_tls(Box::new(TlsEvent {
        domain: "foobar.org".to_string(),
        policy: PolicyType::Sts(None),
        failure: None,
        tls_record: tls_record.clone(),
        interval: AggregateFrequency::Daily,
    }))
    .await;
    core.schedule_tls(Box::new(TlsEvent {
        domain: "foobar.org".to_string(),
        policy: PolicyType::None,
        failure: None,
        tls_record: tls_record.clone(),
        interval: AggregateFrequency::Daily,
    }))
    .await;

    // Verify sizes and counts
    let mut total_tls = 0;
    let mut total_tls_policies = 0;
    let mut total_dmarc_policies = 0;
    let mut last_domain = String::new();
    for report in qr.read_report_events().await {
        match report {
            QueueClass::DmarcReportHeader(event) => {
                total_dmarc_policies += 1;
                assert_eq!(event.due - event.seq_id, 7 * 86400);
            }
            QueueClass::TlsReportHeader(event) => {
                if event.domain != last_domain {
                    last_domain.clone_from(&event.domain);
                    total_tls += 1;
                }
                total_tls_policies += 1;
                assert_eq!(event.due - event.seq_id, 86400);
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(total_tls, 1);
    assert_eq!(total_tls_policies, 3);
    assert_eq!(total_dmarc_policies, 2);
}

#[test]
fn report_strip_json() {
    let mut d = DmarcFormat {
        rua: vec![
            URI {
                uri: "hello".to_string(),
                max_size: 0,
            },
            URI {
                uri: "world".to_string(),
                max_size: 0,
            },
        ],
        policy: PolicyPublished {
            domain: "example.org".to_string(),
            version_published: None,
            adkim: Alignment::Relaxed,
            aspf: Alignment::Strict,
            p: Disposition::Quarantine,
            sp: Disposition::Reject,
            testing: false,
            fo: None,
        },
        records: vec![Record::default()
            .with_count(1)
            .with_envelope_from("domain.net")
            .with_envelope_to("other.org")],
    };
    let mut s = serde_json::to_string(&d).unwrap();
    s.truncate(s.len() - 2);

    let r = Record::default()
        .with_count(2)
        .with_envelope_from("otherdomain.net")
        .with_envelope_to("otherother.org");
    let rs = serde_json::to_string(&r).unwrap();

    d.records.push(r);

    assert_eq!(
        serde_json::from_str::<DmarcFormat>(&format!("{s},{rs}]}}")).unwrap(),
        d
    );
}
