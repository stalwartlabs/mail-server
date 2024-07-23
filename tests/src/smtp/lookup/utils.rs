/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::{
    config::smtp::{
        report::AggregateFrequency,
        resolver::{Mode, MxPattern, Policy},
    },
    Core,
};
use mail_auth::MX;

use ::smtp::outbound::NextHop;
use mail_parser::DateTime;
use smtp::{
    core::Inner,
    outbound::{lookup::ToNextHop, mta_sts::parse::ParsePolicy},
    queue::RecipientDomain,
    reporting::AggregateTimestamp,
};
use utils::config::Config;

use crate::smtp::build_smtp;

const CONFIG_V4: &str = r#"
[queue.outbound.source-ip]
v4 = "['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']"
v6 = "['a:b::1', 'a:b::2', 'a:b::3', 'a:b::4']"

[queue.outbound]
ip-strategy = "ipv4_then_ipv6"

"#;

const CONFIG_V6: &str = r#"
[queue.outbound.source-ip]
v4 = "['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']"
v6 = "['a:b::1', 'a:b::2', 'a:b::3', 'a:b::4']"

[queue.outbound]
ip-strategy = "ipv6_then_ipv4"

"#;

#[tokio::test]
async fn lookup_ip() {
    let ipv6 = [
        "a:b::1".parse().unwrap(),
        "a:b::2".parse().unwrap(),
        "a:b::3".parse().unwrap(),
        "a:b::4".parse().unwrap(),
    ];
    let ipv4 = [
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "10.0.0.3".parse().unwrap(),
        "10.0.0.4".parse().unwrap(),
    ];
    let mut config = Config::new(CONFIG_V4).unwrap();
    let core = build_smtp(
        Core::parse(&mut config, Default::default(), Default::default()).await,
        Inner::default(),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec![
            "172.168.0.100".parse().unwrap(),
            "172.168.0.101".parse().unwrap(),
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.ipv6_add(
        "mx.foobar.org",
        vec!["e:f::a".parse().unwrap(), "e:f::b".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Ipv4 strategy
    let resolve_result = core
        .resolve_host(
            &NextHop::MX("mx.foobar.org"),
            &RecipientDomain::new("envelope"),
            2,
            0,
        )
        .await
        .unwrap();
    assert!(ipv4.contains(&match resolve_result.source_ipv4.unwrap() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    }));
    assert!(resolve_result
        .remote_ips
        .contains(&"172.168.0.100".parse().unwrap()));

    // Ipv6 strategy
    let mut config = Config::new(CONFIG_V6).unwrap();
    let core = build_smtp(
        Core::parse(&mut config, Default::default(), Default::default()).await,
        Inner::default(),
    );
    core.core.smtp.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec![
            "172.168.0.100".parse().unwrap(),
            "172.168.0.101".parse().unwrap(),
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.core.smtp.resolvers.dns.ipv6_add(
        "mx.foobar.org",
        vec!["e:f::a".parse().unwrap(), "e:f::b".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    let resolve_result = core
        .resolve_host(
            &NextHop::MX("mx.foobar.org"),
            &RecipientDomain::new("envelope"),
            2,
            0,
        )
        .await
        .unwrap();
    assert!(ipv6.contains(&match resolve_result.source_ipv6.unwrap() {
        std::net::IpAddr::V6(v6) => v6,
        _ => unreachable!(),
    }));
    assert!(resolve_result
        .remote_ips
        .contains(&"e:f::a".parse().unwrap()));
}

#[test]
fn to_remote_hosts() {
    let mx = vec![
        MX {
            exchanges: vec!["mx1".to_string(), "mx2".to_string()],
            preference: 10,
        },
        MX {
            exchanges: vec![
                "mx3".to_string(),
                "mx4".to_string(),
                "mx5".to_string(),
                "mx6".to_string(),
            ],
            preference: 20,
        },
        MX {
            exchanges: vec!["mx7".to_string(), "mx8".to_string()],
            preference: 10,
        },
        MX {
            exchanges: vec!["mx9".to_string(), "mxA".to_string()],
            preference: 10,
        },
    ];
    let hosts = mx.to_remote_hosts("domain", 7).unwrap();
    assert_eq!(hosts.len(), 7);
    for host in hosts {
        if let NextHop::MX(host) = host {
            assert!((*host.as_bytes().last().unwrap() - b'0') <= 8);
        }
    }
    let mx = vec![MX {
        exchanges: vec![".".to_string()],
        preference: 0,
    }];
    assert!(mx.to_remote_hosts("domain", 10).is_none());
}

#[test]
fn parse_policy() {
    for (policy, expected_policy) in [
        (
            r"version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.net
mx: backupmx.example.com
max_age: 604800",
            Policy {
                id: "abc".to_string(),
                mode: Mode::Enforce,
                mx: vec![
                    MxPattern::Equals("mail.example.com".to_string()),
                    MxPattern::StartsWith("example.net".to_string()),
                    MxPattern::Equals("backupmx.example.com".to_string()),
                ],
                max_age: 604800,
            },
        ),
        (
            r"version: STSv1
mode: testing
mx: gmail-smtp-in.l.google.com
mx: *.gmail-smtp-in.l.google.com
max_age: 86400
",
            Policy {
                id: "abc".to_string(),
                mode: Mode::Testing,
                mx: vec![
                    MxPattern::Equals("gmail-smtp-in.l.google.com".to_string()),
                    MxPattern::StartsWith("gmail-smtp-in.l.google.com".to_string()),
                ],
                max_age: 86400,
            },
        ),
    ] {
        assert_eq!(
            Policy::parse(policy, expected_policy.id.to_string()).unwrap(),
            expected_policy
        );
    }
}

#[test]
fn aggregate_to_timestamp() {
    for (freq, date, expected) in [
        (
            AggregateFrequency::Hourly,
            "2023-01-24T09:10:40Z",
            "2023-01-24T09:00:00Z",
        ),
        (
            AggregateFrequency::Daily,
            "2023-01-24T09:10:40Z",
            "2023-01-24T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-24T09:10:40Z",
            "2023-01-22T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-28T23:59:59Z",
            "2023-01-22T00:00:00Z",
        ),
        (
            AggregateFrequency::Weekly,
            "2023-01-22T23:59:59Z",
            "2023-01-22T00:00:00Z",
        ),
    ] {
        assert_eq!(
            DateTime::from_timestamp(
                freq.to_timestamp_(DateTime::parse_rfc3339(date).unwrap()) as i64
            )
            .to_rfc3339(),
            expected,
            "failed for {freq:?} {date} {expected}"
        );
    }
}
