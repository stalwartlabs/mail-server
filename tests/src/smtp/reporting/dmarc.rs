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
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::Dmarc,
    report::{ActionDisposition, Disposition, DmarcResult, Record, Report},
};
use utils::config::DynValue;

use crate::smtp::{
    inbound::{sign::TextConfigContext, TestMessage, TestQueueEvent},
    make_temp_dir,
    session::VerifyResponse,
    ParseTestConfig, TestConfig, TestSMTP,
};
use smtp::{
    config::{AggregateFrequency, ConfigContext, IfBlock},
    core::SMTP,
    reporting::{
        dmarc::GenerateDmarcReport,
        scheduler::{ReportType, Scheduler},
        DmarcEvent,
    },
};

#[tokio::test]
async fn report_dmarc() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Create scheduler
    let mut core = SMTP::test();
    let ctx = ConfigContext::new(&[]).parse_signatures();
    let temp_dir = make_temp_dir("smtp_report_dmarc_test", true);
    let config = &mut core.report.config;
    config.path = IfBlock::new(temp_dir.temp_dir.clone());
    config.hash = IfBlock::new(16);
    config.dmarc_aggregate.sign = "['rsa']"
        .parse_if::<Vec<DynValue>>(&ctx)
        .map_if_block(&ctx.signers, "", "")
        .unwrap();
    config.dmarc_aggregate.max_size = IfBlock::new(4096);
    config.submitter = IfBlock::new("mx.example.org".to_string());
    config.dmarc_aggregate.address = IfBlock::new("reports@example.org".to_string());
    config.dmarc_aggregate.org_name = IfBlock::new("Foobar, Inc.".to_string().into());
    config.dmarc_aggregate.contact_info =
        IfBlock::new("https://foobar.org/contact".to_string().into());
    let mut scheduler = Scheduler::default();

    // Authorize external report for foobar.org
    core.resolvers.dns.txt_add(
        "foobar.org._report._dmarc.foobar.net",
        Dmarc::parse(b"v=DMARC1;").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    // Create temp dir for queue
    let mut qr = core.init_test_queue("smtp_report_dmarc_test");
    let core = Arc::new(core);

    // Schedule two events with a same policy and another one with a different policy
    let dmarc_record = Arc::new(
        Dmarc::parse(
            b"v=DMARC1; p=quarantine; rua=mailto:reports@foobar.net,mailto:reports@example.net",
        )
        .unwrap(),
    );
    assert_eq!(dmarc_record.rua().len(), 2);
    for _ in 0..2 {
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
    assert_eq!(scheduler.reports.len(), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let report_path;
    match scheduler.reports.into_iter().next().unwrap() {
        (ReportType::Dmarc(domain), ReportType::Dmarc(path)) => {
            report_path = path.path.clone();
            core.generate_dmarc_report(domain, path);
        }
        _ => unreachable!(),
    }

    // Expect report
    let message = qr.read_event().await.unwrap_message();
    qr.assert_empty_queue();
    assert_eq!(message.recipients.len(), 1);
    assert_eq!(
        message.recipients.last().unwrap().address,
        "reports@foobar.net"
    );
    assert_eq!(message.return_path, "reports@example.org");
    message
        .read_lines()
        .assert_contains("DKIM-Signature: v=1; a=rsa-sha256; s=rsa; d=example.com;")
        .assert_contains("To: <reports@foobar.net>")
        .assert_contains("Report Domain: foobar.org")
        .assert_contains("Submitter: mx.example.org");

    // Verify generated report
    let report = Report::parse_rfc5322(message.read_message().as_bytes()).unwrap();
    assert_eq!(report.domain(), "foobar.org");
    assert_eq!(report.email(), "reports@example.org");
    assert_eq!(report.org_name(), "Foobar, Inc.");
    assert_eq!(
        report.extra_contact_info().unwrap(),
        "https://foobar.org/contact"
    );
    assert_eq!(report.p(), Disposition::Quarantine);
    assert_eq!(report.records().len(), 2);
    for record in report.records() {
        let source_ip = record.source_ip().unwrap();
        if source_ip == "192.168.1.2".parse::<IpAddr>().unwrap() {
            assert_eq!(record.count(), 2);
            assert_eq!(record.action_disposition(), ActionDisposition::Pass);
            assert_eq!(record.envelope_from(), "hello@example.org");
            assert_eq!(record.header_from(), "bye@example.org");
            assert_eq!(record.envelope_to().unwrap(), "other@example.org");
        } else if source_ip == "a:b:c::e:f".parse::<IpAddr>().unwrap() {
            assert_eq!(record.count(), 1);
            assert_eq!(record.action_disposition(), ActionDisposition::Reject);
        } else {
            panic!("unexpected ip {source_ip}");
        }
    }

    assert!(!report_path.exists());
}
