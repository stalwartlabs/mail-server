use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use tokio::net::TcpSocket;

use utils::config::{Config, Listener, Rate, Server, ServerProtocol};

use ahash::{AHashMap, AHashSet};
use directory::Lookup;

use smtp::config::{
    condition::ConfigCondition, if_block::ConfigIf, throttle::ConfigThrottle, Condition,
    ConditionMatch, Conditions, ConfigContext, EnvelopeKey, IfBlock, IfThen, IpAddrMask,
    StringMatch, Throttle, THROTTLE_AUTH_AS, THROTTLE_REMOTE_IP, THROTTLE_SENDER_DOMAIN,
};

use super::add_test_certs;

#[test]
fn parse_conditions() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("rules.toml");

    let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
    let servers = vec![Server {
        id: "smtp".to_string(),
        internal_id: 123,
        ..Default::default()
    }];
    let mut context = ConfigContext::new(&servers);
    let list = Arc::new(Lookup::List {
        list: AHashSet::new(),
    });
    context
        .directory
        .lookups
        .insert("test-list".to_string(), list.clone());

    let mut conditions = config.parse_conditions(&context).unwrap();
    let expected_rules = AHashMap::from_iter([
        (
            "simple".to_string(),
            Conditions {
                conditions: vec![Condition::Match {
                    key: EnvelopeKey::Listener,
                    value: ConditionMatch::UInt(123),
                    not: false,
                }],
            },
        ),
        (
            "is-authenticated".to_string(),
            Conditions {
                conditions: vec![Condition::Match {
                    key: EnvelopeKey::AuthenticatedAs,
                    value: ConditionMatch::String(StringMatch::Equal("".to_string())),
                    not: true,
                }],
            },
        ),
        (
            "expanded".to_string(),
            Conditions {
                conditions: vec![
                    Condition::Match {
                        key: EnvelopeKey::SenderDomain,
                        value: ConditionMatch::String(StringMatch::StartsWith(
                            "example".to_string(),
                        )),
                        not: false,
                    },
                    Condition::JumpIfFalse { positions: 1 },
                    Condition::Match {
                        key: EnvelopeKey::Sender,
                        value: ConditionMatch::Lookup(list),
                        not: false,
                    },
                ],
            },
        ),
        (
            "my-nested-rule".to_string(),
            Conditions {
                conditions: vec![
                    Condition::Match {
                        key: EnvelopeKey::RecipientDomain,
                        value: ConditionMatch::String(StringMatch::Equal(
                            "example.org".to_string(),
                        )),
                        not: false,
                    },
                    Condition::JumpIfTrue { positions: 9 },
                    Condition::Match {
                        key: EnvelopeKey::RemoteIp,
                        value: ConditionMatch::IpAddrMask(IpAddrMask::V4 {
                            addr: "192.168.0.0".parse().unwrap(),
                            mask: u32::MAX << (32 - 24),
                        }),
                        not: false,
                    },
                    Condition::JumpIfTrue { positions: 7 },
                    Condition::Match {
                        key: EnvelopeKey::Recipient,
                        value: ConditionMatch::String(StringMatch::StartsWith(
                            "no-reply@".to_string(),
                        )),
                        not: false,
                    },
                    Condition::JumpIfFalse { positions: 5 },
                    Condition::Match {
                        key: EnvelopeKey::Sender,
                        value: ConditionMatch::String(StringMatch::EndsWith(
                            "@domain.org".to_string(),
                        )),
                        not: false,
                    },
                    Condition::JumpIfFalse { positions: 3 },
                    Condition::Match {
                        key: EnvelopeKey::Priority,
                        value: ConditionMatch::Int(1),
                        not: true,
                    },
                    Condition::JumpIfTrue { positions: 1 },
                    Condition::Match {
                        key: EnvelopeKey::Priority,
                        value: ConditionMatch::Int(-2),
                        not: false,
                    },
                ],
            },
        ),
    ]);

    for (key, rule) in expected_rules {
        assert_eq!(Some(rule), conditions.remove(&key), "failed for {key}");
    }
}

#[test]
fn parse_if_blocks() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("if-blocks.toml");

    let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();

    // Create context and add some conditions
    let context = ConfigContext::new(&[]);
    let available_keys = vec![
        EnvelopeKey::Recipient,
        EnvelopeKey::RecipientDomain,
        EnvelopeKey::Sender,
        EnvelopeKey::SenderDomain,
        EnvelopeKey::AuthenticatedAs,
        EnvelopeKey::Listener,
        EnvelopeKey::RemoteIp,
        EnvelopeKey::LocalIp,
        EnvelopeKey::Priority,
    ];

    assert_eq!(
        config
            .parse_if_block::<Option<Duration>>("durations", &context, &available_keys)
            .unwrap()
            .unwrap(),
        IfBlock {
            if_then: vec![
                IfThen {
                    conditions: Conditions {
                        conditions: vec![Condition::Match {
                            key: EnvelopeKey::Sender,
                            value: ConditionMatch::String(StringMatch::Equal("jdoe".to_string())),
                            not: false
                        }]
                    },
                    then: Duration::from_secs(5 * 86400).into()
                },
                IfThen {
                    conditions: Conditions {
                        conditions: vec![
                            Condition::Match {
                                key: EnvelopeKey::Priority,
                                value: ConditionMatch::Int(-1),
                                not: false
                            },
                            Condition::JumpIfTrue { positions: 1 },
                            Condition::Match {
                                key: EnvelopeKey::Recipient,
                                value: ConditionMatch::String(StringMatch::StartsWith(
                                    "jane".to_string()
                                )),
                                not: false
                            }
                        ]
                    },
                    then: Duration::from_secs(3600).into()
                }
            ],
            default: None
        }
    );

    assert_eq!(
        config
            .parse_if_block::<Vec<String>>("string-list", &context, &available_keys)
            .unwrap()
            .unwrap(),
        IfBlock {
            if_then: vec![
                IfThen {
                    conditions: Conditions {
                        conditions: vec![Condition::Match {
                            key: EnvelopeKey::Sender,
                            value: ConditionMatch::String(StringMatch::Equal("jdoe".to_string())),
                            not: false
                        }]
                    },
                    then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                },
                IfThen {
                    conditions: Conditions {
                        conditions: vec![
                            Condition::Match {
                                key: EnvelopeKey::Priority,
                                value: ConditionMatch::Int(-1),
                                not: false
                            },
                            Condition::JumpIfTrue { positions: 1 },
                            Condition::Match {
                                key: EnvelopeKey::Recipient,
                                value: ConditionMatch::String(StringMatch::StartsWith(
                                    "jane".to_string()
                                )),
                                not: false
                            }
                        ]
                    },
                    then: vec!["Other-ID".to_string()]
                }
            ],
            default: vec![]
        }
    );

    assert_eq!(
        config
            .parse_if_block::<Vec<String>>("string-list-bis", &context, &available_keys)
            .unwrap()
            .unwrap(),
        IfBlock {
            if_then: vec![
                IfThen {
                    conditions: Conditions {
                        conditions: vec![Condition::Match {
                            key: EnvelopeKey::Sender,
                            value: ConditionMatch::String(StringMatch::Equal("jdoe".to_string())),
                            not: false
                        }]
                    },
                    then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                },
                IfThen {
                    conditions: Conditions {
                        conditions: vec![
                            Condition::Match {
                                key: EnvelopeKey::Priority,
                                value: ConditionMatch::Int(-1),
                                not: false
                            },
                            Condition::JumpIfTrue { positions: 1 },
                            Condition::Match {
                                key: EnvelopeKey::Recipient,
                                value: ConditionMatch::String(StringMatch::StartsWith(
                                    "jane".to_string()
                                )),
                                not: false
                            }
                        ]
                    },
                    then: vec![]
                }
            ],
            default: vec!["ID-Bis".to_string()]
        }
    );

    assert_eq!(
        config
            .parse_if_block::<String>("single-value", &context, &available_keys)
            .unwrap()
            .unwrap(),
        IfBlock {
            if_then: vec![],
            default: "hello world".to_string()
        }
    );

    for bad_rule in [
        "bad-multi-value",
        "bad-if-without-then",
        "bad-if-without-else",
        "bad-multiple-else",
    ] {
        if let Ok(value) = config.parse_if_block::<u32>(bad_rule, &context, &available_keys) {
            panic!("Condition {bad_rule:?} had unexpected result {value:?}");
        }
    }
}

#[test]
fn parse_throttle() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("throttle.toml");

    let available_keys = vec![
        EnvelopeKey::Recipient,
        EnvelopeKey::RecipientDomain,
        EnvelopeKey::Sender,
        EnvelopeKey::SenderDomain,
        EnvelopeKey::AuthenticatedAs,
        EnvelopeKey::Listener,
        EnvelopeKey::RemoteIp,
        EnvelopeKey::LocalIp,
        EnvelopeKey::Priority,
    ];

    let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
    let context = ConfigContext::new(&[]);
    let throttle = config
        .parse_throttle("throttle", &context, &available_keys, u16::MAX)
        .unwrap();

    assert_eq!(
        throttle,
        vec![
            Throttle {
                conditions: Conditions {
                    conditions: vec![Condition::Match {
                        key: EnvelopeKey::RemoteIp,
                        value: ConditionMatch::IpAddrMask(IpAddrMask::V4 {
                            addr: "127.0.0.1".parse().unwrap(),
                            mask: u32::MAX
                        }),
                        not: false
                    }]
                },
                keys: THROTTLE_REMOTE_IP | THROTTLE_AUTH_AS,
                concurrency: 100.into(),
                rate: Rate {
                    requests: 50,
                    period: Duration::from_secs(30)
                }
                .into()
            },
            Throttle {
                conditions: Conditions { conditions: vec![] },
                keys: THROTTLE_SENDER_DOMAIN,
                concurrency: 10000.into(),
                rate: None
            }
        ]
    );
}

#[test]
fn parse_servers() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("servers.toml");

    let toml = add_test_certs(&fs::read_to_string(file).unwrap());

    // Parse servers
    let config = Config::parse(&toml).unwrap();
    let servers = config.parse_servers().unwrap().inner;
    let expected_servers = vec![
        Server {
            id: "smtp".to_string(),
            internal_id: 0,
            hostname: "mx.example.org".to_string(),
            data: "Stalwart SMTP - hi there!".to_string(),
            protocol: ServerProtocol::Smtp,
            listeners: vec![Listener {
                socket: TcpSocket::new_v4().unwrap(),
                addr: "127.0.0.1:9925".parse().unwrap(),
                ttl: 3600.into(),
                backlog: 1024.into(),
            }],
            tls: None,
            tls_implicit: false,
            max_connections: 8192,
        },
        Server {
            id: "smtps".to_string(),
            internal_id: 1,
            hostname: "mx.example.org".to_string(),
            data: "Stalwart SMTP - hi there!".to_string(),
            protocol: ServerProtocol::Smtp,
            listeners: vec![
                Listener {
                    socket: TcpSocket::new_v4().unwrap(),
                    addr: "127.0.0.1:9465".parse().unwrap(),
                    ttl: 4096.into(),
                    backlog: 1024.into(),
                },
                Listener {
                    socket: TcpSocket::new_v4().unwrap(),
                    addr: "127.0.0.1:9466".parse().unwrap(),
                    ttl: 4096.into(),
                    backlog: 1024.into(),
                },
            ],
            tls: None,
            tls_implicit: true,
            max_connections: 1024,
        },
        Server {
            id: "submission".to_string(),
            internal_id: 2,
            hostname: "submit.example.org".to_string(),
            data: "Stalwart SMTP submission at your service".to_string(),
            protocol: ServerProtocol::Smtp,
            listeners: vec![Listener {
                socket: TcpSocket::new_v4().unwrap(),
                addr: "127.0.0.1:9991".parse().unwrap(),
                ttl: 3600.into(),
                backlog: 2048.into(),
            }],
            tls: None,
            tls_implicit: true,
            max_connections: 8192,
        },
    ];

    for (server, expected_server) in servers.into_iter().zip(expected_servers) {
        assert_eq!(
            server.id, expected_server.id,
            "failed for {}",
            expected_server.id
        );
        assert_eq!(
            server.internal_id, expected_server.internal_id,
            "failed for {}",
            expected_server.id
        );
        assert_eq!(
            server.hostname, expected_server.hostname,
            "failed for {}",
            expected_server.id
        );
        assert_eq!(
            server.data, expected_server.data,
            "failed for {}",
            expected_server.id
        );
        assert_eq!(
            server.protocol, expected_server.protocol,
            "failed for {}",
            expected_server.id
        );
        assert_eq!(
            server.tls_implicit, expected_server.tls_implicit,
            "failed for {}",
            expected_server.id
        );
        for (listener, expected_listener) in
            server.listeners.into_iter().zip(expected_server.listeners)
        {
            assert_eq!(
                listener.addr, expected_listener.addr,
                "failed for {}",
                expected_server.id
            );
            assert_eq!(
                listener.ttl, expected_listener.ttl,
                "failed for {}",
                expected_server.id
            );
            assert_eq!(
                listener.backlog, expected_listener.backlog,
                "failed for {}",
                expected_server.id
            );
        }
    }
}
