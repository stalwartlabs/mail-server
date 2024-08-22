/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, path::PathBuf, sync::Arc};

use common::{
    config::server::ServerProtocol,
    listener::{limiter::ConcurrencyLimiter, ServerInstance, SessionStream, TcpAcceptor},
};
use rustls::{server::ResolvesServerCert, ServerConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
};

use smtp::core::{Session, SessionAddress, SessionData, SessionParameters, State, SMTP};
use tokio_rustls::TlsAcceptor;
use utils::snowflake::SnowflakeIdGenerator;

pub struct DummyIo {
    pub tx_buf: Vec<u8>,
    pub rx_buf: Vec<u8>,
    pub tls: bool,
}

impl AsyncRead for DummyIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.rx_buf.is_empty() {
            buf.put_slice(&self.rx_buf);
            self.rx_buf.clear();
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl AsyncWrite for DummyIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.tx_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl SessionStream for DummyIo {
    fn is_tls(&self) -> bool {
        self.tls
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        ("".into(), "".into())
    }
}

impl Unpin for DummyIo {}

#[allow(async_fn_in_trait)]
pub trait TestSession {
    fn test(core: SMTP) -> Self;
    fn test_with_shutdown(core: SMTP, shutdown_rx: watch::Receiver<bool>) -> Self;
    fn response(&mut self) -> Vec<String>;
    fn write_rx(&mut self, data: &str);
    async fn rset(&mut self);
    async fn cmd(&mut self, cmd: &str, expected_code: &str) -> Vec<String>;
    async fn ehlo(&mut self, host: &str) -> Vec<String>;
    async fn mail_from(&mut self, from: &str, expected_code: &str);
    async fn rcpt_to(&mut self, to: &str, expected_code: &str);
    async fn data(&mut self, data: &str, expected_code: &str);
    async fn send_message(&mut self, from: &str, to: &[&str], data: &str, expected_code: &str);
    async fn test_builder(&self);
}

impl TestSession for Session<DummyIo> {
    fn test_with_shutdown(core: SMTP, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            state: State::default(),
            instance: Arc::new(ServerInstance::test_with_shutdown(shutdown_rx)),
            core,
            stream: DummyIo {
                rx_buf: vec![],
                tx_buf: vec![],
                tls: false,
            },
            data: SessionData::new(
                "127.0.0.1".parse().unwrap(),
                0,
                "127.0.0.1".parse().unwrap(),
                0,
                0,
            ),
            params: SessionParameters::default(),
            in_flight: vec![],
            hostname: "localhost".to_string(),
        }
    }

    fn test(core: SMTP) -> Self {
        Self::test_with_shutdown(core, watch::channel(false).1)
    }

    fn response(&mut self) -> Vec<String> {
        if !self.stream.tx_buf.is_empty() {
            let response = std::str::from_utf8(&self.stream.tx_buf)
                .unwrap()
                .split("\r\n")
                .filter_map(|r| {
                    if !r.is_empty() {
                        r.to_string().into()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            self.stream.tx_buf.clear();
            response
        } else {
            panic!("There was no response.");
        }
    }

    fn write_rx(&mut self, data: &str) {
        self.stream.rx_buf.extend_from_slice(data.as_bytes());
    }

    async fn rset(&mut self) {
        self.ingest(b"RSET\r\n").await.unwrap();
        self.response().assert_code("250");
    }

    async fn cmd(&mut self, cmd: &str, expected_code: &str) -> Vec<String> {
        self.ingest(format!("{cmd}\r\n").as_bytes()).await.unwrap();
        self.response().assert_code(expected_code)
    }

    async fn ehlo(&mut self, host: &str) -> Vec<String> {
        self.ingest(format!("EHLO {host}\r\n").as_bytes())
            .await
            .unwrap();
        self.response().assert_code("250")
    }

    async fn mail_from(&mut self, from: &str, expected_code: &str) {
        self.ingest(
            if !from.starts_with('<') {
                format!("MAIL FROM:<{from}>\r\n")
            } else {
                format!("MAIL FROM:{from}\r\n")
            }
            .as_bytes(),
        )
        .await
        .unwrap();
        self.response().assert_code(expected_code);
    }

    async fn rcpt_to(&mut self, to: &str, expected_code: &str) {
        self.ingest(
            if !to.starts_with('<') {
                format!("RCPT TO:<{to}>\r\n")
            } else {
                format!("RCPT TO:{to}\r\n")
            }
            .as_bytes(),
        )
        .await
        .unwrap();
        self.response().assert_code(expected_code);
    }

    async fn data(&mut self, data: &str, expected_code: &str) {
        self.ingest(b"DATA\r\n").await.unwrap();
        self.response().assert_code("354");
        if let Some(file) = data.strip_prefix("test:") {
            self.ingest(load_test_message(file, "messages").as_bytes())
                .await
                .unwrap();
        } else if let Some(file) = data.strip_prefix("report:") {
            self.ingest(load_test_message(file, "reports").as_bytes())
                .await
                .unwrap();
        } else {
            self.ingest(data.as_bytes()).await.unwrap();
        }
        self.ingest(b"\r\n.\r\n").await.unwrap();
        self.response().assert_code(expected_code);
    }

    async fn send_message(&mut self, from: &str, to: &[&str], data: &str, expected_code: &str) {
        self.mail_from(from, "250").await;
        for to in to {
            self.rcpt_to(to, "250").await;
        }
        self.data(data, expected_code).await;
    }

    async fn test_builder(&self) {
        let message = self
            .build_message(
                SessionAddress {
                    address: "bill@foobar.org".to_string(),
                    address_lcase: "bill@foobar.org".to_string(),
                    domain: "foobar.org".to_string(),
                    flags: 123,
                    dsn_info: "envelope1".to_string().into(),
                },
                vec![
                    SessionAddress {
                        address: "a@foobar.org".to_string(),
                        address_lcase: "a@foobar.org".to_string(),
                        domain: "foobar.org".to_string(),
                        flags: 1,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "b@test.net".to_string(),
                        address_lcase: "b@test.net".to_string(),
                        domain: "test.net".to_string(),
                        flags: 2,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "c@foobar.org".to_string(),
                        address_lcase: "c@foobar.org".to_string(),
                        domain: "foobar.org".to_string(),
                        flags: 3,
                        dsn_info: None,
                    },
                    SessionAddress {
                        address: "d@test.net".to_string(),
                        address_lcase: "d@test.net".to_string(),
                        domain: "test.net".to_string(),
                        flags: 4,
                        dsn_info: None,
                    },
                ],
                self.core.inner.queue_id_gen.generate().unwrap(),
                0,
            )
            .await;
        assert_eq!(
            message
                .domains
                .iter()
                .map(|d| d.domain.clone())
                .collect::<Vec<_>>(),
            vec!["foobar.org".to_string(), "test.net".to_string()]
        );
        let rcpts = ["a@foobar.org", "b@test.net", "c@foobar.org", "d@test.net"];
        let domain_idx = [0, 1, 0, 1];
        for rcpt in &message.recipients {
            let idx = (rcpt.flags - 1) as usize;
            assert_eq!(rcpts[idx], rcpt.address);
            assert_eq!(domain_idx[idx], rcpt.domain_idx);
        }
    }
}

pub fn load_test_message(file: &str, test: &str) -> String {
    let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_file.push("resources");
    test_file.push("smtp");
    test_file.push(test);
    test_file.push(format!("{file}.eml"));
    std::fs::read_to_string(test_file).unwrap()
}

pub trait VerifyResponse {
    fn assert_code(self, expected_code: &str) -> Self;
    fn assert_contains(self, expected_text: &str) -> Self;
    fn assert_not_contains(self, expected_text: &str) -> Self;
    fn assert_count(self, text: &str, occurrences: usize) -> Self;
}

impl VerifyResponse for Vec<String> {
    fn assert_code(self, expected_code: &str) -> Self {
        if self.last().expect("response").starts_with(expected_code) {
            self
        } else {
            panic!("Expected {:?} but got {}.", expected_code, self.join("\n"));
        }
    }

    fn assert_contains(self, expected_text: &str) -> Self {
        if self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!("Expected {:?} but got {}.", expected_text, self.join("\n"));
        }
    }

    fn assert_not_contains(self, expected_text: &str) -> Self {
        if !self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!(
                "Not expecting {:?} but got it {}.",
                expected_text,
                self.join("\n")
            );
        }
    }

    fn assert_count(self, text: &str, occurrences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurrences,
            "Expected {} occurrences of {:?}, found {}.",
            occurrences,
            text,
            self.iter().filter(|l| l.contains(text)).count()
        );
        self
    }
}

pub trait TestServerInstance {
    fn test_with_shutdown(shutdown_rx: watch::Receiver<bool>) -> Self;
}

impl TestServerInstance for ServerInstance {
    fn test_with_shutdown(shutdown_rx: watch::Receiver<bool>) -> Self {
        let tls_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(DummyCertResolver)),
        );

        Self {
            id: "smtp".to_string(),
            protocol: ServerProtocol::Smtp,
            acceptor: TcpAcceptor::Tls {
                config: tls_config.clone(),
                acceptor: TlsAcceptor::from(tls_config),
                implicit: false,
            },
            limiter: ConcurrencyLimiter::new(100),
            shutdown_rx,
            proxy_networks: vec![],
            span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
        }
    }
}

#[derive(Debug)]
pub struct DummyCertResolver;

impl ResolvesServerCert for DummyCertResolver {
    fn resolve(&self, _: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

pub fn test_server_instance() -> ServerInstance {
    ServerInstance::test_with_shutdown(watch::channel(false).1)
}
