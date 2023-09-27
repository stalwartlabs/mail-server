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
    borrow::Cow,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use tokio::net::TcpSocket;

use utils::config::{Config, DynValue, KeyLookup, Listener, Rate, Server, ServerProtocol};

use ahash::AHashMap;
use directory::{config::ConfigDirectory, Lookup, LookupList};

use smtp::config::{
    condition::ConfigCondition, if_block::ConfigIf, throttle::ConfigThrottle, Condition,
    ConditionMatch, Conditions, ConfigContext, EnvelopeKey, IfBlock, IfThen, IpAddrMask,
    StringMatch, Throttle, THROTTLE_AUTH_AS, THROTTLE_REMOTE_IP, THROTTLE_SENDER_DOMAIN,
};

use super::add_test_certs;

struct TestEnvelope {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub sender_domain: String,
    pub sender: String,
    pub rcpt_domain: String,
    pub rcpt: String,
    pub helo_domain: String,
    pub authenticated_as: String,
    pub mx: String,
    pub listener_id: u16,
    pub priority: i16,
}

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
        list: LookupList::default(),
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
                linger: None,
                nodelay: true,
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
                    linger: None,
                    nodelay: true,
                },
                Listener {
                    socket: TcpSocket::new_v4().unwrap(),
                    addr: "127.0.0.1:9466".parse().unwrap(),
                    ttl: 4096.into(),
                    backlog: 1024.into(),
                    linger: None,
                    nodelay: true,
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
                linger: None,
                nodelay: true,
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

#[tokio::test]
async fn eval_if() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("rules-eval.toml");

    let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
    let servers = vec![
        Server {
            id: "smtp".to_string(),
            internal_id: 123,
            ..Default::default()
        },
        Server {
            id: "smtps".to_string(),
            internal_id: 456,
            ..Default::default()
        },
    ];
    let mut context = ConfigContext::new(&servers);
    context.directory = config.parse_directory().unwrap();
    let conditions = config.parse_conditions(&context).unwrap();

    let envelope = TestEnvelope::from_config(&config);

    for (key, conditions) in conditions {
        //println!("============= Testing {:?} ==================", key);
        let (_, expected_result) = key.rsplit_once('-').unwrap();
        assert_eq!(
            IfBlock {
                if_then: vec![IfThen {
                    conditions,
                    then: true
                }],
                default: false,
            }
            .eval(&envelope)
            .await,
            &expected_result.parse::<bool>().unwrap(),
            "failed for {key:?}"
        );
    }
}

#[tokio::test]
async fn eval_dynvalue() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("rules-dynvalue.toml");

    let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
    let mut context = ConfigContext::new(&[]);
    context.directory = config.parse_directory().unwrap();

    let envelope = TestEnvelope::from_config(&config);

    for test_name in config.sub_keys("eval") {
        //println!("============= Testing {:?} ==================", key);
        let if_block = config
            .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                ("eval", test_name, "test"),
                &context,
                &[
                    EnvelopeKey::Recipient,
                    EnvelopeKey::RecipientDomain,
                    EnvelopeKey::Sender,
                    EnvelopeKey::SenderDomain,
                    EnvelopeKey::AuthenticatedAs,
                    EnvelopeKey::Listener,
                    EnvelopeKey::RemoteIp,
                    EnvelopeKey::LocalIp,
                    EnvelopeKey::Priority,
                    EnvelopeKey::Mx,
                ],
            )
            .unwrap()
            .unwrap();
        let expected = config
            .property_require::<Option<String>>(("eval", test_name, "expect"))
            .unwrap()
            .map(Cow::Owned);

        assert_eq!(
            if_block
                .eval_and_capture(&envelope)
                .await
                .into_value(&envelope),
            expected,
            "failed for test {test_name:?}"
        );
    }

    for test_name in config.sub_keys("maybe-eval") {
        //println!("============= Testing {:?} ==================", key);
        let if_block = config
            .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                ("maybe-eval", test_name, "test"),
                &context,
                &[
                    EnvelopeKey::Recipient,
                    EnvelopeKey::RecipientDomain,
                    EnvelopeKey::Sender,
                    EnvelopeKey::SenderDomain,
                    EnvelopeKey::AuthenticatedAs,
                    EnvelopeKey::Listener,
                    EnvelopeKey::RemoteIp,
                    EnvelopeKey::LocalIp,
                    EnvelopeKey::Priority,
                    EnvelopeKey::Mx,
                ],
            )
            .unwrap()
            .unwrap()
            .map_if_block(
                &context.directory.directories,
                ("maybe-eval", test_name, "test"),
                "test",
            )
            .unwrap();
        let expected = config
            .value_require(("maybe-eval", test_name, "expect"))
            .unwrap();

        assert!(if_block
            .eval_and_capture(&envelope)
            .await
            .into_value(&envelope)
            .unwrap()
            .is_local_domain(expected)
            .await
            .unwrap());
    }
}

impl KeyLookup for TestEnvelope {
    type Key = EnvelopeKey;

    fn key(&self, key: &Self::Key) -> std::borrow::Cow<'_, str> {
        match key {
            EnvelopeKey::Recipient => self.rcpt.as_str().into(),
            EnvelopeKey::RecipientDomain => self.rcpt_domain.as_str().into(),
            EnvelopeKey::Sender => self.sender.as_str().into(),
            EnvelopeKey::SenderDomain => self.sender_domain.as_str().into(),
            EnvelopeKey::AuthenticatedAs => self.authenticated_as.as_str().into(),
            EnvelopeKey::Listener => self.listener_id.to_string().into(),
            EnvelopeKey::RemoteIp => self.remote_ip.to_string().into(),
            EnvelopeKey::LocalIp => self.local_ip.to_string().into(),
            EnvelopeKey::Priority => self.priority.to_string().into(),
            EnvelopeKey::Mx => self.mx.as_str().into(),
            EnvelopeKey::HeloDomain => self.helo_domain.as_str().into(),
        }
    }

    fn key_as_int(&self, key: &Self::Key) -> i32 {
        match key {
            EnvelopeKey::Priority => self.priority as i32,
            EnvelopeKey::Listener => self.listener_id as i32,
            _ => todo!(),
        }
    }

    fn key_as_ip(&self, key: &Self::Key) -> IpAddr {
        match key {
            EnvelopeKey::RemoteIp => self.remote_ip,
            EnvelopeKey::LocalIp => self.local_ip,
            _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        }
    }
}

impl TestEnvelope {
    pub fn from_config(config: &Config) -> Self {
        Self {
            local_ip: config.property_require("envelope.local-ip").unwrap(),
            remote_ip: config.property_require("envelope.remote-ip").unwrap(),
            sender_domain: config.property_require("envelope.sender-domain").unwrap(),
            sender: config.property_require("envelope.sender").unwrap(),
            rcpt_domain: config.property_require("envelope.rcpt-domain").unwrap(),
            rcpt: config.property_require("envelope.rcpt").unwrap(),
            authenticated_as: config
                .property_require("envelope.authenticated-as")
                .unwrap(),
            mx: config.property_require("envelope.mx").unwrap(),
            listener_id: config.property_require("envelope.listener").unwrap(),
            priority: config.property_require("envelope.priority").unwrap(),
            helo_domain: config.property_require("envelope.helo-domain").unwrap(),
        }
    }
}
