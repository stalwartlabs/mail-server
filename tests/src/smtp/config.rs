use std::{fs, path::PathBuf};

use tokio::net::TcpSocket;

use utils::config::{Config, Listener, Server, ServerProtocol};

use super::add_test_certs;

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
