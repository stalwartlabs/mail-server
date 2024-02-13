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

use std::{fs, net::IpAddr, path::PathBuf, time::Duration};

use store::config::ConfigStore;
use tokio::net::TcpSocket;

use utils::{
    config::{
        if_block::{IfBlock, IfThen},
        Config, Listener, Rate, Server, ServerProtocol,
    },
    expr::{BinaryOperator, Constant, Expression, ExpressionItem, UnaryOperator},
    listener::TcpAcceptor,
};

use smtp::{
    config::{
        map_expr_token, throttle::ConfigThrottle, ConfigContext, Throttle, THROTTLE_AUTH_AS,
        THROTTLE_REMOTE_IP, THROTTLE_SENDER_DOMAIN,
    },
    core::{eval::*, ResolveVariable},
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
    pub listener_id: String,
    pub priority: i16,
}

#[test]
fn parse_if_blocks() {
    let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file.push("resources");
    file.push("smtp");
    file.push("config");
    file.push("if-blocks.toml");

    let config = Config::new(&fs::read_to_string(file).unwrap()).unwrap();

    // Create context and add some conditions
    let available_keys = vec![
        V_RECIPIENT,
        V_RECIPIENT_DOMAIN,
        V_SENDER,
        V_SENDER_DOMAIN,
        V_AUTHENTICATED_AS,
        V_LISTENER,
        V_REMOTE_IP,
        V_LOCAL_IP,
        V_PRIORITY,
    ];

    assert_eq!(
        config
            .parse_if_block("durations", |name| {
                map_expr_token::<Duration>(name, &available_keys)
            })
            .unwrap()
            .unwrap(),
        IfBlock {
            key: "durations".to_string(),
            if_then: vec![
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(2),
                            ExpressionItem::Constant(Constant::String("jdoe".to_string())),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq)
                        ]
                    },
                    then: Expression {
                        items: vec![ExpressionItem::Constant(Constant::Integer(432000000))]
                    }
                },
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(10),
                            ExpressionItem::Constant(Constant::Integer(1)),
                            ExpressionItem::UnaryOperator(UnaryOperator::Minus),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq),
                            ExpressionItem::JmpIf { val: true, pos: 4 },
                            ExpressionItem::Variable(0),
                            ExpressionItem::Constant(Constant::String("jane".to_string())),
                            ExpressionItem::Function {
                                id: 29,
                                num_args: 2
                            },
                            ExpressionItem::BinaryOperator(BinaryOperator::Or)
                        ]
                    },
                    then: Expression {
                        items: vec![ExpressionItem::Constant(Constant::Integer(3600000))]
                    }
                }
            ],
            default: Expression {
                items: vec![ExpressionItem::Constant(Constant::Integer(0))]
            }
        }
    );

    assert_eq!(
        config
            .parse_if_block("string-list", |name| {
                map_expr_token::<Duration>(name, &available_keys)
            })
            .unwrap()
            .unwrap(),
        IfBlock {
            key: "string-list".to_string(),
            if_then: vec![
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(2),
                            ExpressionItem::Constant(Constant::String("jdoe".to_string())),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq)
                        ]
                    },
                    then: Expression {
                        items: vec![
                            ExpressionItem::Constant(Constant::String("From".to_string())),
                            ExpressionItem::Constant(Constant::String("To".to_string())),
                            ExpressionItem::Constant(Constant::String("Date".to_string())),
                            ExpressionItem::ArrayBuild(3)
                        ]
                    }
                },
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(10),
                            ExpressionItem::Constant(Constant::Integer(1)),
                            ExpressionItem::UnaryOperator(UnaryOperator::Minus),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq),
                            ExpressionItem::JmpIf { val: true, pos: 4 },
                            ExpressionItem::Variable(0),
                            ExpressionItem::Constant(Constant::String("jane".to_string())),
                            ExpressionItem::Function {
                                id: 29,
                                num_args: 2
                            },
                            ExpressionItem::BinaryOperator(BinaryOperator::Or)
                        ]
                    },
                    then: Expression {
                        items: vec![ExpressionItem::Constant(Constant::String(
                            "Other-ID".to_string()
                        ))]
                    }
                }
            ],
            default: Expression {
                items: vec![ExpressionItem::ArrayBuild(0)]
            }
        }
    );

    assert_eq!(
        config
            .parse_if_block("string-list-bis", |name| {
                map_expr_token::<Duration>(name, &available_keys)
            })
            .unwrap()
            .unwrap(),
        IfBlock {
            key: "string-list-bis".to_string(),
            if_then: vec![
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(2),
                            ExpressionItem::Constant(Constant::String("jdoe".to_string())),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq)
                        ]
                    },
                    then: Expression {
                        items: vec![
                            ExpressionItem::Constant(Constant::String("From".to_string())),
                            ExpressionItem::Constant(Constant::String("To".to_string())),
                            ExpressionItem::Constant(Constant::String("Date".to_string())),
                            ExpressionItem::ArrayBuild(3)
                        ]
                    }
                },
                IfThen {
                    expr: Expression {
                        items: vec![
                            ExpressionItem::Variable(10),
                            ExpressionItem::Constant(Constant::Integer(1)),
                            ExpressionItem::UnaryOperator(UnaryOperator::Minus),
                            ExpressionItem::BinaryOperator(BinaryOperator::Eq),
                            ExpressionItem::JmpIf { val: true, pos: 4 },
                            ExpressionItem::Variable(0),
                            ExpressionItem::Constant(Constant::String("jane".to_string())),
                            ExpressionItem::Function {
                                id: 29,
                                num_args: 2
                            },
                            ExpressionItem::BinaryOperator(BinaryOperator::Or)
                        ]
                    },
                    then: Expression {
                        items: vec![ExpressionItem::ArrayBuild(0)]
                    }
                }
            ],
            default: Expression {
                items: vec![
                    ExpressionItem::Constant(Constant::String("ID-Bis".to_string())),
                    ExpressionItem::ArrayBuild(1)
                ]
            }
        }
    );

    assert_eq!(
        config
            .parse_if_block("single-value", |name| {
                map_expr_token::<Duration>(name, &available_keys)
            })
            .unwrap()
            .unwrap(),
        IfBlock {
            key: "single-value".to_string(),
            if_then: vec![],
            default: Expression {
                items: vec![ExpressionItem::Constant(Constant::String(
                    "hello world".to_string()
                ))]
            }
        }
    );

    for bad_rule in [
        "bad-if-without-then",
        "bad-if-without-else",
        "bad-multiple-else",
    ] {
        if let Ok(value) = config.parse_if_block(bad_rule, |name| {
            map_expr_token::<Duration>(name, &available_keys)
        }) {
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
        V_RECIPIENT,
        V_RECIPIENT_DOMAIN,
        V_SENDER,
        V_SENDER_DOMAIN,
        V_AUTHENTICATED_AS,
        V_LISTENER,
        V_REMOTE_IP,
        V_LOCAL_IP,
        V_PRIORITY,
    ];

    let config = Config::new(&fs::read_to_string(file).unwrap()).unwrap();
    let throttle = config
        .parse_throttle("throttle", &available_keys, u16::MAX)
        .unwrap();

    assert_eq!(
        throttle,
        vec![
            Throttle {
                expr: Expression {
                    items: vec![
                        ExpressionItem::Variable(8),
                        ExpressionItem::Constant(Constant::String("127.0.0.1".to_string())),
                        ExpressionItem::BinaryOperator(BinaryOperator::Eq)
                    ]
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
                expr: Expression::default(),
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
    let config = Config::new(&toml).unwrap();
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
            acceptor: TcpAcceptor::Plain,
            tls_implicit: false,
            max_connections: 8192,
            proxy_networks: vec![],
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
            acceptor: TcpAcceptor::Plain,
            tls_implicit: true,
            max_connections: 1024,
            proxy_networks: vec![],
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
            acceptor: TcpAcceptor::Plain,
            tls_implicit: true,
            max_connections: 8192,
            proxy_networks: vec![],
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

    let config = Config::new(&fs::read_to_string(file).unwrap()).unwrap();
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
    context.stores = config.parse_stores().await.unwrap();

    let envelope = TestEnvelope::from_config(&config);

    for (key, expr) in &config.keys {
        if !key.starts_with("rule.") {
            continue;
        }

        //println!("============= Testing {:?} ==================", key);
        let (_, expected_result) = key.rsplit_once('-').unwrap();
        assert_eq!(
            IfBlock {
                key: key.to_string(),
                if_then: vec![IfThen {
                    expr: Expression::parse(key.as_str(), expr, |name| {
                        map_expr_token::<Duration>(
                            name,
                            &[
                                V_RECIPIENT,
                                V_RECIPIENT_DOMAIN,
                                V_SENDER,
                                V_SENDER_DOMAIN,
                                V_AUTHENTICATED_AS,
                                V_LISTENER,
                                V_REMOTE_IP,
                                V_LOCAL_IP,
                                V_PRIORITY,
                                V_MX,
                            ],
                        )
                    })
                    .unwrap(),
                    then: Expression::from(true),
                }],
                default: Expression::from(false),
            }
            .eval(
                |name| { envelope.resolve_variable(name) },
                |_, _| async { Default::default() }
            )
            .await
            .to_bool(),
            expected_result.parse::<bool>().unwrap(),
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

    let config = Config::new(&fs::read_to_string(file).unwrap()).unwrap();
    let mut context = ConfigContext::new(&[]);
    context.stores = config.parse_stores().await.unwrap();

    let envelope = TestEnvelope::from_config(&config);

    for test_name in config.sub_keys("eval", "") {
        //println!("============= Testing {:?} ==================", key);
        let if_block = config
            .parse_if_block(("eval", test_name, "test"), |name| {
                map_expr_token::<Duration>(
                    name,
                    &[
                        V_RECIPIENT,
                        V_RECIPIENT_DOMAIN,
                        V_SENDER,
                        V_SENDER_DOMAIN,
                        V_AUTHENTICATED_AS,
                        V_LISTENER,
                        V_REMOTE_IP,
                        V_LOCAL_IP,
                        V_PRIORITY,
                        V_MX,
                    ],
                )
            })
            .unwrap()
            .unwrap();
        let expected = config
            .property_require::<Option<String>>(("eval", test_name, "expect"))
            .unwrap();

        assert_eq!(
            String::try_from(
                if_block
                    .eval(
                        |name| { envelope.resolve_variable(name) },
                        |_, _| async { Default::default() }
                    )
                    .await
            )
            .ok(),
            expected,
            "failed for test {test_name:?}"
        );
    }
}

impl ResolveVariable for TestEnvelope {
    fn resolve_variable(&self, variable: u32) -> utils::expr::Variable<'_> {
        match variable {
            V_RECIPIENT => self.rcpt.as_str().into(),
            V_RECIPIENT_DOMAIN => self.rcpt_domain.as_str().into(),
            V_SENDER => self.sender.as_str().into(),
            V_SENDER_DOMAIN => self.sender_domain.as_str().into(),
            V_AUTHENTICATED_AS => self.authenticated_as.as_str().into(),
            V_LISTENER => self.listener_id.to_string().into(),
            V_REMOTE_IP => self.remote_ip.to_string().into(),
            V_LOCAL_IP => self.local_ip.to_string().into(),
            V_PRIORITY => self.priority.to_string().into(),
            V_MX => self.mx.as_str().into(),
            V_HELO_DOMAIN => self.helo_domain.as_str().into(),
            _ => Default::default(),
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
