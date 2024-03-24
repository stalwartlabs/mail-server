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

use ahash::{AHashMap, HashSet};
use common::{
    config::{server::ServerProtocol, smtp::report::AggregateFrequency},
    expr::if_block::IfBlock,
};
use directory::core::config::ConfigDirectory;
use mail_auth::{
    common::parse::TxtRecordParser,
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{
        tlsrpt::{FailureDetails, ResultType},
        ActionDisposition, DmarcResult, Record,
    },
};
use reqwest::Method;
use store::Store;
use tokio::sync::mpsc;
use utils::config::Config;

use crate::smtp::{
    inbound::dummy_stores,
    management::{queue::List, send_manage_request},
    outbound::start_test_server,
    TestConfig,
};
use smtp::{
    core::{management::Report, SMTP},
    reporting::{scheduler::SpawnReport, DmarcEvent, TlsEvent},
};

const DIRECTORY: &str = r#"
[storage]
lookup = "dummy"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "admin"
type = "admin"
description = "Superuser"
secret = "secret"
member-of = ["superusers"]

"#;

#[tokio::test]
#[serial_test::serial]
async fn manage_reports() {
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Start reporting service
    let mut core = SMTP::test();
    let config = &mut core.core.smtp.report;
    config.dmarc_aggregate.max_size = IfBlock::new(1024);
    config.tls.max_size = IfBlock::new(1024);
    let directory = Config::new(DIRECTORY)
        .unwrap()
        .parse_directory(&dummy_stores(), Store::default())
        .await
        .unwrap();
    core.core.storage.directory = directory.directories.get("local").unwrap().clone();
    let (report_tx, report_rx) = mpsc::channel(1024);
    core.report.tx = report_tx;
    let core = Arc::new(core);
    report_rx.spawn(core.clone());
    let _rx_manage = start_test_server(core.clone(), &[ServerProtocol::Http]);

    // Send test reporting events
    core.schedule_report(DmarcEvent {
        domain: "foobar.org".to_string(),
        report_record: Record::new()
            .with_source_ip("192.168.1.2".parse().unwrap())
            .with_action_disposition(ActionDisposition::Pass)
            .with_dmarc_dkim_result(DmarcResult::Pass)
            .with_dmarc_spf_result(DmarcResult::Fail)
            .with_envelope_from("hello@example.org")
            .with_envelope_to("other@example.org")
            .with_header_from("bye@example.org"),
        dmarc_record: Arc::new(
            Dmarc::parse(b"v=DMARC1; p=reject; rua=mailto:reports@foobar.org").unwrap(),
        ),
        interval: AggregateFrequency::Daily,
    })
    .await;
    core.schedule_report(DmarcEvent {
        domain: "foobar.net".to_string(),
        report_record: Record::new()
            .with_source_ip("a:b:c::e:f".parse().unwrap())
            .with_action_disposition(ActionDisposition::Reject)
            .with_dmarc_dkim_result(DmarcResult::Fail)
            .with_dmarc_spf_result(DmarcResult::Pass),
        dmarc_record: Arc::new(
            Dmarc::parse(
                b"v=DMARC1; p=quarantine; rua=mailto:reports@foobar.net,mailto:reports@example.net",
            )
            .unwrap(),
        ),
        interval: AggregateFrequency::Weekly,
    })
    .await;
    core.schedule_report(TlsEvent {
        domain: "foobar.org".to_string(),
        policy: smtp::reporting::PolicyType::None,
        failure: None,
        tls_record: Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.org").unwrap()),
        interval: AggregateFrequency::Daily,
    })
    .await;
    core.schedule_report(TlsEvent {
        domain: "foobar.net".to_string(),
        policy: smtp::reporting::PolicyType::Sts(None),
        failure: FailureDetails::new(ResultType::StsPolicyInvalid).into(),
        tls_record: Arc::new(TlsRpt::parse(b"v=TLSRPTv1;rua=mailto:reports@foobar.net").unwrap()),
        interval: AggregateFrequency::Weekly,
    })
    .await;

    // List reports
    let ids = send_manage_request::<List<String>>(Method::GET, "/api/queue/reports")
        .await
        .unwrap()
        .unwrap_data()
        .items;
    assert_eq!(ids.len(), 4);
    let mut id_map = AHashMap::new();
    let mut id_map_rev = AHashMap::new();
    for (report, id) in get_reports(&ids).await.into_iter().zip(ids) {
        let mut parts = id.split('!');
        let report = report.unwrap();
        let mut id_num = if parts.next().unwrap() == "t" {
            assert!(matches!(report, Report::Tls { .. }));
            2
        } else {
            assert!(matches!(report, Report::Dmarc { .. }));
            0
        };
        let (domain, range_to, range_from) = match report {
            Report::Dmarc {
                domain,
                range_to,
                range_from,
                ..
            } => (domain, range_to, range_from),
            Report::Tls {
                domain,
                range_to,
                range_from,
                ..
            } => (domain, range_to, range_from),
        };
        assert_eq!(parts.next().unwrap(), domain);
        let diff = range_to.to_timestamp() - range_from.to_timestamp();
        if domain == "foobar.org" {
            assert_eq!(diff, 86400);
        } else {
            assert_eq!(diff, 7 * 86400);
            id_num += 1;
        }
        id_map.insert(char::from(b'a' + id_num).to_string(), id.clone());
        id_map_rev.insert(id, char::from(b'a' + id_num).to_string());
    }

    // Test list search
    for (query, expected_ids) in [
        ("/api/queue/reports?type=dmarc", vec!["a", "b"]),
        ("/api/queue/reports?type=tls", vec!["c", "d"]),
        ("/api/queue/reports?domain=foobar.org", vec!["a", "c"]),
        ("/api/queue/reports?domain=foobar.net", vec!["b", "d"]),
        ("/api/queue/reports?domain=foobar.org&type=dmarc", vec!["a"]),
        ("/api/queue/reports?domain=foobar.net&type=tls", vec!["d"]),
    ] {
        let expected_ids = HashSet::from_iter(expected_ids.into_iter().map(|s| s.to_string()));
        let ids = send_manage_request::<List<String>>(Method::GET, query)
            .await
            .unwrap()
            .unwrap_data()
            .items
            .into_iter()
            .map(|id| id_map_rev.get(&id).unwrap().clone())
            .collect::<HashSet<_>>();
        assert_eq!(ids, expected_ids, "failed for {query}");
    }

    // Cancel reports
    for id in ["a", "b"] {
        assert!(
            send_manage_request::<bool>(
                Method::DELETE,
                &format!("/api/queue/reports/{}", id_map.get(id).unwrap(),)
            )
            .await
            .unwrap()
            .unwrap_data(),
            "failed for {id}"
        );
    }
    assert_eq!(
        send_manage_request::<List<String>>(Method::GET, "/api/queue/reports")
            .await
            .unwrap()
            .unwrap_data()
            .items
            .len(),
        2
    );
    let mut ids = get_reports(&[
        id_map.get("a").unwrap().clone(),
        id_map.get("b").unwrap().clone(),
        id_map.get("c").unwrap().clone(),
        id_map.get("d").unwrap().clone(),
    ])
    .await
    .into_iter();
    assert!(ids.next().unwrap().is_none());
    assert!(ids.next().unwrap().is_none());
    assert!(ids.next().unwrap().is_some());
    assert!(ids.next().unwrap().is_some());
}

async fn get_reports(ids: &[String]) -> Vec<Option<Report>> {
    let mut results = Vec::with_capacity(ids.len());

    for id in ids {
        let report =
            send_manage_request::<Report>(Method::GET, &format!("/api/queue/reports/{id}",))
                .await
                .unwrap()
                .try_unwrap_data();
        results.push(report);
    }

    results
}
