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

use std::sync::Arc;

use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::{Dmarc, URI},
    mta_sts::TlsRpt,
    report::{ActionDisposition, Alignment, Disposition, DmarcResult, PolicyPublished, Record},
};
use tokio::fs;
use utils::config::if_block::IfBlock;

use crate::smtp::{make_temp_dir, TestConfig};
use smtp::{
    config::AggregateFrequency,
    core::SMTP,
    reporting::{
        dmarc::DmarcFormat,
        scheduler::{ReportType, Scheduler},
        DmarcEvent, PolicyType, TlsEvent,
    },
};

#[tokio::test]
async fn report_scheduler() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Create scheduler
    let mut core = SMTP::test();
    let temp_dir = make_temp_dir("smtp_report_scheduler_test", true);
    let config = &mut core.report.config;
    config.path = temp_dir.temp_dir.clone();
    config.hash = IfBlock::new(16);
    config.dmarc_aggregate.max_size = IfBlock::new(500);
    config.tls.max_size = IfBlock::new(550);
    let mut scheduler = Scheduler::default();

    // Schedule two events with a same policy and another one with a different policy
    let dmarc_record =
        Arc::new(Dmarc::parse(b"v=DMARC1; p=quarantine; rua=mailto:dmarc@foobar.org").unwrap());
    scheduler
        .schedule_dmarc(
            Box::new(DmarcEvent {
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
            }),
            &core,
        )
        .await;

    // No records should be added once the 550 bytes max size is reached
    for _ in 0..10 {
        scheduler
            .schedule_dmarc(
                Box::new(DmarcEvent {
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
                }),
                &core,
            )
            .await;
    }
    let dmarc_record =
        Arc::new(Dmarc::parse(b"v=DMARC1; p=reject; rua=mailto:dmarc@foobar.org").unwrap());
    scheduler
        .schedule_dmarc(
            Box::new(DmarcEvent {
                domain: "foobar.org".to_string(),
                report_record: Record::new()
                    .with_source_ip("a:b:c::e:f".parse().unwrap())
                    .with_action_disposition(ActionDisposition::Reject)
                    .with_dmarc_dkim_result(DmarcResult::Fail)
                    .with_dmarc_spf_result(DmarcResult::Pass),
                dmarc_record: dmarc_record.clone(),
                interval: AggregateFrequency::Weekly,
            }),
            &core,
        )
        .await;

    // Schedule TLS event
    let tls_record = Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap());
    scheduler
        .schedule_tls(
            Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: PolicyType::Tlsa(None),
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
            }),
            &core,
        )
        .await;
    scheduler
        .schedule_tls(
            Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: PolicyType::Tlsa(None),
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
            }),
            &core,
        )
        .await;
    scheduler
        .schedule_tls(
            Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: PolicyType::Sts(None),
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
            }),
            &core,
        )
        .await;
    scheduler
        .schedule_tls(
            Box::new(TlsEvent {
                domain: "foobar.org".to_string(),
                policy: PolicyType::None,
                failure: None,
                tls_record: tls_record.clone(),
                interval: AggregateFrequency::Daily,
            }),
            &core,
        )
        .await;

    // Verify sizes and counts
    let mut total_tls = 0;
    let mut total_tls_policies = 0;
    let mut total_dmarc_policies = 0;
    for report in scheduler.reports.values() {
        match report {
            ReportType::Dmarc(r) => {
                assert!(r.size <= 550, "{}", r.size);
                assert_eq!(fs::metadata(&r.path).await.unwrap().len() as usize, r.size);
                assert_eq!(r.deliver_at, AggregateFrequency::Weekly);
                total_dmarc_policies += 1;
            }
            ReportType::Tls(r) => {
                total_tls += 1;
                total_tls_policies += r.path.len();
                assert!(r.size <= 550);
                assert_eq!(r.deliver_at, AggregateFrequency::Daily);
                let mut sizes = 0;
                for p in &r.path {
                    sizes += fs::metadata(&p.inner).await.unwrap().len() as usize;
                }
                assert_eq!(r.size, sizes);
            }
        }
    }
    assert_eq!(total_tls, 1);
    assert_eq!(total_tls_policies, 3);
    assert_eq!(total_dmarc_policies, 2);

    // Verify deserialized report queue
    let mut scheduler_deser = core.report.read_reports().await;
    for (key, value) in scheduler.reports {
        let a = Some(value);
        let b = scheduler_deser.reports.remove(&key);
        match (&a, &b) {
            (Some(ReportType::Tls(a)), Some(ReportType::Tls(b))) => {
                assert_eq!(a.created, b.created);
                assert_eq!(a.size, b.size);
                assert_eq!(a.deliver_at, b.deliver_at);
                assert_eq!(a.path.len(), b.path.len());
                for p in &a.path {
                    assert!(b.path.contains(p));
                }
                for p in &b.path {
                    assert!(a.path.contains(p));
                }
            }
            _ => {
                assert_eq!(a, b, "failed for {key:?}");
            }
        }
    }
    assert_eq!(scheduler.main.len(), scheduler_deser.main.len());
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
