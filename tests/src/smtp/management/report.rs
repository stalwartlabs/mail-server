/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::{AHashMap, HashSet};
use common::config::{server::ServerProtocol, smtp::report::AggregateFrequency};

use jmap::api::management::queue::Report;
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

use crate::{
    jmap::ManagementApi,
    smtp::{management::queue::List, outbound::TestServer},
};
use smtp::reporting::{scheduler::SpawnReport, DmarcEvent, TlsEvent};

const CONFIG: &str = r#"
[storage]
directory = "local"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "admin"
type = "admin"
description = "Superuser"
secret = "secret"
class = "admin"

[session.rcpt]
relay = true

[report.dmarc.aggregate]
max-size = 1024

[report.tls.aggregate]
max-size = 1024
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
    let local = TestServer::new("smtp_manage_reports", CONFIG, true).await;
    let _rx = local.start(&[ServerProtocol::Http]).await;
    let core = local.build_smtp();
    local.rr.report_rx.spawn(local.instance.clone());

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
    let api = ManagementApi::default();
    let ids = api
        .request::<List<String>>(Method::GET, "/api/queue/reports")
        .await
        .unwrap()
        .unwrap_data()
        .items;
    assert_eq!(ids.len(), 4);
    let mut id_map = AHashMap::new();
    let mut id_map_rev = AHashMap::new();
    for (report, id) in api.get_reports(&ids).await.into_iter().zip(ids) {
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
        let ids = api
            .request::<List<String>>(Method::GET, query)
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
            api.request::<bool>(
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
        api.request::<List<String>>(Method::GET, "/api/queue/reports")
            .await
            .unwrap()
            .unwrap_data()
            .items
            .len(),
        2
    );
    let mut ids = api
        .get_reports(&[
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

impl ManagementApi {
    async fn get_reports(&self, ids: &[String]) -> Vec<Option<Report>> {
        let mut results = Vec::with_capacity(ids.len());

        for id in ids {
            let report = self
                .request::<Report>(Method::GET, &format!("/api/queue/reports/{id}",))
                .await
                .unwrap()
                .try_unwrap_data();
            results.push(report);
        }

        results
    }
}
