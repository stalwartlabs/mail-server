use std::time::{Duration, Instant};

use mail_auth::{IpLookupStrategy, MX};

use smtp::{config::IfBlock, core::Core, outbound::RemoteHost};

use super::ToRemoteHost;

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
    let mut core = Core::test();
    core.queue.config.source_ip.ipv4 = IfBlock::new(ipv4.clone());
    core.queue.config.source_ip.ipv6 = IfBlock::new(ipv6.clone());
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
    let (source_ips, remote_ips) = core
        .resolve_host(&RemoteHost::MX("mx.foobar.org"), &"envelope", 2)
        .await
        .unwrap();
    assert!(ipv4.contains(&match source_ips.unwrap() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    }));
    assert!(remote_ips.contains(&"172.168.0.100".parse().unwrap()));

    // Ipv6 strategy
    core.queue.config.ip_strategy = IfBlock::new(IpLookupStrategy::Ipv6thenIpv4);
    let (source_ips, remote_ips) = core
        .resolve_host(&RemoteHost::MX("mx.foobar.org"), &"envelope", 2)
        .await
        .unwrap();
    assert!(ipv6.contains(&match source_ips.unwrap() {
        std::net::IpAddr::V6(v6) => v6,
        _ => unreachable!(),
    }));
    assert!(remote_ips.contains(&"e:f::a".parse().unwrap()));
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
        if let RemoteHost::MX(host) = host {
            assert!((*host.as_bytes().last().unwrap() - b'0') <= 8);
        }
    }
    let mx = vec![MX {
        exchanges: vec![".".to_string()],
        preference: 0,
    }];
    assert!(mx.to_remote_hosts("domain", 10).is_none());
}
