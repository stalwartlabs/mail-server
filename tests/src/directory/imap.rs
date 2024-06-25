/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::listener::limiter::{ConcurrencyLimiter, InFlight};
use directory::QueryBy;
use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use crate::directory::{DirectoryTest, Item, LookupResult};

use super::dummy_tls_acceptor;

#[tokio::test]
async fn imap_directory() {
    // Enable logging
    /*tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    )
    .unwrap();*/

    // Spawn mock LMTP server
    let shutdown = spawn_mock_imap_server(5);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Obtain directory handle
    let mut config = DirectoryTest::new(None).await;
    let handle = config.directories.directories.remove("imap").unwrap();

    // Basic lookup
    let tests = vec![
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".to_string(),
                secret: "ok".to_string(),
            }),
            LookupResult::True,
        ),
        (
            Item::Authenticate(Credentials::Plain {
                username: "john".to_string(),
                secret: "bad".to_string(),
            }),
            LookupResult::False,
        ),
    ];

    for (item, expected) in &tests {
        assert_eq!(
            &LookupResult::from(
                handle
                    .query(QueryBy::Credentials(item.as_credentials()), true)
                    .await
                    .unwrap()
                    .is_some()
            ),
            expected
        );
    }

    // Concurrent requests
    let mut requests = Vec::new();
    for n in 0..10 {
        let (item, expected) = &tests[n % tests.len()];
        let item = item.append(n);
        let item_clone = item.clone();
        let handle = handle.clone();
        requests.push((
            tokio::spawn(async move {
                LookupResult::from(
                    handle
                        .query(QueryBy::Credentials(item.as_credentials()), true)
                        .await
                        .unwrap()
                        .is_some(),
                )
            }),
            item_clone,
            expected.append(n),
        ));
    }
    for (result, item, expected_result) in requests {
        assert_eq!(
            result.await.unwrap(),
            expected_result,
            "Failed for {item:?}"
        );
    }

    // Shutdown
    shutdown.send(false).ok();
}

pub fn spawn_mock_imap_server(max_concurrency: u64) -> watch::Sender<bool> {
    let (tx, mut rx) = watch::channel(true);

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9198")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock IMAP server to 127.0.0.1:9198: {e}");
            });
        let acceptor = dummy_tls_acceptor();
        let limited = ConcurrencyLimiter::new(max_concurrency);
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            //println!("--- Accepted connection --- ");
                            let acceptor = acceptor.clone();
                            let in_flight = limited.is_allowed();
                            tokio::spawn(accept_imap(stream, acceptor, in_flight));
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx.changed() => {
                    break;
                }
            };
        }
    });

    tx
}

async fn accept_imap(stream: TcpStream, acceptor: Arc<TlsAcceptor>, in_flight: Option<InFlight>) {
    let mut stream = acceptor.accept(stream).await.unwrap();
    stream
        .write_all(b"* OK Clueless host service ready\r\n")
        .await
        .unwrap();

    if in_flight.is_none() {
        eprintln!("WARNING: Concurrency exceeded!");
    }

    let mut buf_u8 = vec![0u8; 1024];

    loop {
        let br = if let Ok(br) = stream.read(&mut buf_u8).await {
            br
        } else {
            break;
        };
        let buf = std::str::from_utf8(&buf_u8[0..br]).unwrap();
        let (op, buf) = buf.split_once(' ').unwrap();

        //print!("-> {}", buf);
        let response = if buf.starts_with("CAPABILITY") {
            format!(
                "* CAPABILITY IMAP4rev2 IMAP4rev1 AUTH=PLAIN\r\n{op} OK CAPABILITY completed\r\n",
            )
        } else if buf.starts_with("NOOP") {
            format!("{op} OK NOOP completed\r\n")
        } else if buf.starts_with("AUTHENTICATE PLAIN") {
            let buf = base64_decode(buf.rsplit_once(' ').unwrap().1.as_bytes()).unwrap();
            if String::from_utf8_lossy(&buf).contains("ok") {
                format!("{op} OK Great success!\r\n")
            } else {
                format!("{op} BAD No soup for you!\r\n")
            }
        } else if buf.starts_with("LOGOUT") {
            format!("* BYE\r\n{op} OK LOGOUT completed\r\n")
        } else {
            panic!("Unknown command: {}", buf.trim());
        };
        //print!("<- {}", response);
        for line in response.split_inclusive('\n') {
            stream.write_all(line.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        if buf.contains("bye") || buf.starts_with("LOGOUT") {
            return;
        }
    }
}
