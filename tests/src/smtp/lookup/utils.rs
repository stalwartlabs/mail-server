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

use std::time::{Duration, Instant};

use mail_auth::{IpLookupStrategy, MX};

use ::smtp::{core::SMTP, outbound::NextHop};
use mail_parser::DateTime;
use smtp::{
    config::AggregateFrequency,
    outbound::{
        lookup::ToNextHop,
        mta_sts::{Mode, MxPattern, Policy},
    },
    queue::RecipientDomain,
};
use utils::config::if_block::IfBlock;

use crate::smtp::{ParseTestConfig, TestConfig};

#[tokio::test]
async fn lookup_ip() {
    let ipv6 = vec![
        "a:b::1".parse().unwrap(),
        "a:b::2".parse().unwrap(),
        "a:b::3".parse().unwrap(),
        "a:b::4".parse().unwrap(),
    ];
    let ipv4 = vec![
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "10.0.0.3".parse().unwrap(),
        "10.0.0.4".parse().unwrap(),
    ];
    let mut core = SMTP::test();
    core.queue.config.source_ip.ipv4 = format!(
        "[{}]",
        ipv4.iter()
            .map(|ip| format!("\"{}\"", ip))
            .collect::<Vec<_>>()
            .join(",")
    )
    .as_str()
    .parse_if();
    core.queue.config.source_ip.ipv6 = format!(
        "[{}]",
        ipv6.iter()
            .map(|ip| format!("\"{}\"", ip))
            .collect::<Vec<_>>()
            .join(",")
    )
    .as_str()
    .parse_if();
    core.resolvers.dns.ipv4_add(
        "mx.foobar.org",
        vec![
            "172.168.0.100".parse().unwrap(),
            "172.168.0.101".parse().unwrap(),
        ],
        Instant::now() + Duration::from_secs(10),
    );
    core.resolvers.dns.ipv6_add(
        "mx.foobar.org",
        vec!["e:f::a".parse().unwrap(), "e:f::b".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    // Ipv4 strategy
    core.queue.config.ip_strategy = IfBlock::new(IpLookupStrategy::Ipv4thenIpv6);
    let resolve_result = core
        .resolve_host(
            &NextHop::MX("mx.foobar.org"),
            &RecipientDomain::new("envelope"),
            2,
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
    core.queue.config.ip_strategy = IfBlock::new(IpLookupStrategy::Ipv6thenIpv4);
    let resolve_result = core
        .resolve_host(
            &NextHop::MX("mx.foobar.org"),
            &RecipientDomain::new("envelope"),
            2,
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
