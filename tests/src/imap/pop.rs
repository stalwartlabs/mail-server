/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::smtp::tls::build_tls_connector;
use rustls_pki_types::ServerName;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{jmap::delivery::SmtpConnection, smtp::session::VerifyResponse};

pub async fn test() {
    println!("Running POP3 tests...");

    // Send 3 test emails
    for i in 0..3 {
        let mut lmtp = SmtpConnection::connect_port(11201).await;
        lmtp.ingest(
            "bill@example.com",
            &["popper@example.com"],
            &format!(
                concat!(
                    "From: bill@example.com\r\n",
                    "To: popper@example.com\r\n",
                    "Subject: TPS Report {}\r\n",
                    "X-Spam-Status: No\r\n",
                    "\r\n",
                    "I'm going to need those TPS {} reports ASAP.\r\n",
                    "..\r\n",
                    "So, if you could do that, that'd be great."
                ),
                i, i
            ),
        )
        .await;
    }

    // Connect to POP3
    let mut pop3 = Pop3Connection::connect().await;
    pop3.assert_read(ResponseType::Ok).await;

    // Capabilities
    pop3.send("CAPA").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("SASL PLAIN")
        .assert_contains("IMPLEMENTATION");

    // Noop
    pop3.send("NOOP").await;
    pop3.assert_read(ResponseType::Ok).await;

    // Authenticate user/pass
    pop3.send("PASS secret").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("USER popper@example.com").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("PASS wrong_secret").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("USER popper@example.com").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("PASS secret").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;

    // Authenticate using AUTH PLAIN
    let mut pop3 = Pop3Connection::connect().await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("AUTH PLAIN AHBvcHBlckBleGFtcGxlLmNvbQBzZWNyZXQ=")
        .await;
    pop3.assert_read(ResponseType::Ok).await;

    // STAT
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 3 546");

    // UTF8
    pop3.send("UTF8").await;
    pop3.assert_read(ResponseType::Ok).await;

    // LIST
    pop3.send("LIST").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 3 messages")
        .assert_contains("1 182")
        .assert_contains("2 182")
        .assert_contains("3 182");
    pop3.send("LIST 2").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 182");

    // UIDL
    pop3.send("UIDL").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 3 messages")
        .assert_contains("1 ")
        .assert_contains("2 ")
        .assert_contains("3 ");
    pop3.send("UIDL 2").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 ");

    // RETR
    pop3.send("RETR 1").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 182 octets")
        .assert_contains("I'm going to need those TPS 0 reports ASAP.")
        .assert_contains("So, if you could do that, that'd be great.");
    pop3.send("RETR 3").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 182 octets")
        .assert_contains("I'm going to need those TPS 2 reports ASAP.")
        .assert_contains("So, if you could do that, that'd be great.");
    pop3.send("RETR 4").await;
    pop3.assert_read(ResponseType::Err).await;

    // TOP
    pop3.send("TOP 1 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 182 octets")
        .assert_contains("Subject: TPS Report 0")
        .assert_not_contains("I'm going to need those TPS 0 reports ASAP.");
    pop3.send("TOP 3 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 182 octets")
        .assert_contains("Subject: TPS Report 2")
        .assert_not_contains("I'm going to need those TPS 2 reports ASAP.");

    // DELE + RSET + QUIT (should not delete messages)
    pop3.send("DELE 1").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("DELE 4").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("RSET").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    let mut pop3 = Pop3Connection::connect_and_login().await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 3 546");

    // DELE + QUIT (should delete messages)
    pop3.send("DELE 2").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    let mut pop3 = Pop3Connection::connect_and_login().await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 364");
    pop3.send("TOP 1 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("TPS Report 0");
    pop3.send("TOP 2 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("TPS Report 2");

    // DELE using pipelining
    pop3.send("DELE 1\r\nDELE 2").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    let mut pop3 = Pop3Connection::connect_and_login().await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 0 0");
    pop3.send("QUIT").await;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    Ok,
    Multiline,
    Err,
}

pub struct Pop3Connection {
    reader: Lines<BufReader<ReadHalf<TlsStream<TcpStream>>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl Pop3Connection {
    pub async fn connect() -> Self {
        let (reader, writer) = tokio::io::split(
            build_tls_connector(true)
                .connect(
                    ServerName::try_from("pop3.example.org").unwrap().to_owned(),
                    TcpStream::connect("127.0.0.1:4110").await.unwrap(),
                )
                .await
                .unwrap(),
        );
        Pop3Connection {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    pub async fn connect_and_login() -> Self {
        let mut pop3 = Self::connect().await;
        pop3.assert_read(ResponseType::Ok).await;
        pop3.send("AUTH PLAIN AHBvcHBlckBleGFtcGxlLmNvbQBzZWNyZXQ=")
            .await;
        pop3.assert_read(ResponseType::Ok).await;
        pop3
    }

    pub async fn assert_read(&mut self, rt: ResponseType) -> Vec<String> {
        let lines = self.read(matches!(rt, ResponseType::Multiline)).await;
        if lines.last().unwrap().starts_with(match rt {
            ResponseType::Ok => "+OK",
            ResponseType::Multiline => ".",
            ResponseType::Err => "-ERR",
        }) {
            lines
        } else {
            panic!("Expected {:?} from server but got: {:?}", rt, lines);
        }
    }

    pub async fn read(&mut self, is_multiline: bool) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = (!is_multiline && line.starts_with("+OK"))
                        || (is_multiline && line == ".")
                        || line.starts_with("-ERR");
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}
