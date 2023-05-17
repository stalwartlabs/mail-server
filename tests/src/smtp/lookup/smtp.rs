/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::sync::Arc;

use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

use smtp::{
    config::{remote::ConfigHost, ConfigContext},
    lookup::{Item, LookupResult},
};
use utils::{
    config::Config,
    listener::limiter::{ConcurrencyLimiter, InFlight},
};

use crate::smtp::lookup::{TestItem, TestLookupResult};

use super::dummy_tls_acceptor;

const REMOTE: &str = "
[remote.lmtp]
address = 127.0.0.1
port = 9999
protocol = 'lmtp'
concurrency = 5

[remote.lmtp.limits]
errors = 3
requests = 5

[remote.lmtp.cache]
entries = 500
ttl = {positive = '10s', negative = '5s'}

[remote.lmtp.tls]
implicit = true
allow-invalid-certs = true
";

#[tokio::test]
async fn lookup_smtp() {
    // Spawn mock LMTP server
    let shutdown = spawn_mock_lmtp_server(5);

    // Spawn lookup client
    let mut ctx = ConfigContext::new(&[]);
    let config = Config::parse(REMOTE).unwrap();
    config.parse_remote_hosts(&mut ctx).unwrap();
    let lookup = ctx.hosts.remove("lmtp").unwrap().spawn(&config);

    // Basic lookup
    let tests = vec![
        (
            Item::IsAccount("john-ok@domain".to_string()),
            LookupResult::True,
        ),
        (
            Item::IsAccount("john-bad@domain".to_string()),
            LookupResult::False,
        ),
        (
            Item::Verify("john-ok@domain".to_string()),
            LookupResult::Values(vec!["john-ok@domain".to_string()]),
        ),
        (
            Item::Verify("doesnot@exist.org".to_string()),
            LookupResult::False,
        ),
        (
            Item::Expand("sales-ok,item1,item2,item3".to_string()),
            LookupResult::Values(vec![
                "sales-ok".to_string(),
                "item1".to_string(),
                "item2".to_string(),
                "item3".to_string(),
            ]),
        ),
        (Item::Expand("other".to_string()), LookupResult::False),
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
        assert_eq!(&lookup.lookup(item.clone()).await.unwrap(), expected);
    }

    // Concurrent requests
    let mut requests = Vec::new();
    for n in 0..100 {
        let (item, expected) = &tests[n % tests.len()];
        let item = item.append(n);
        let item_clone = item.clone();
        let lookup = lookup.clone();
        requests.push((
            tokio::spawn(async move { lookup.lookup(item).await }),
            item_clone,
            expected.append(n),
        ));
    }
    for (result, item, expected_result) in requests {
        let result = result.await.unwrap();
        assert_eq!(result, Some(expected_result), "Failed for {item:?}");
    }

    // Shutdown
    shutdown.send(false).ok();

    // Verify that caching works
    TcpStream::connect("127.0.0.1:9999").await.unwrap_err();

    let mut requests = Vec::new();
    for n in 0..100 {
        let (item, expected) = &tests[n % tests.len()];
        if !matches!(item, Item::Verify(_) | Item::Expand(_)) {
            let item = item.append(n);
            let item_clone = item.clone();
            let lookup = lookup.clone();
            requests.push((
                tokio::spawn(async move { lookup.lookup(item).await }),
                item_clone,
                expected.append(n),
            ));
        }
    }
    for (result, item, expected_result) in requests {
        let result = result.await.unwrap();
        assert_eq!(result, Some(expected_result), "Failed for {item:?}");
    }
}

pub fn spawn_mock_lmtp_server(max_concurrency: u64) -> watch::Sender<bool> {
    let (tx, mut rx) = watch::channel(true);

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9999")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock SMTP server to 127.0.0.1:9999: {e}");
            });
        let acceptor = dummy_tls_acceptor();
        let limited = ConcurrencyLimiter::new(max_concurrency);
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            let acceptor = acceptor.clone();
                            let in_flight = limited.is_allowed();
                            tokio::spawn(accept_smtp(stream, acceptor, in_flight));
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

async fn accept_smtp(stream: TcpStream, acceptor: Arc<TlsAcceptor>, in_flight: Option<InFlight>) {
    let mut stream = acceptor.accept(stream).await.unwrap();
    stream
        .write_all(b"220 [127.0.0.1] Clueless host service ready\r\n")
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
        //print!("-> {}", buf);
        let response = if buf.starts_with("LHLO") {
            "250-mx.foobar.org\r\n250 AUTH PLAIN\r\n".to_string()
        } else if buf.starts_with("MAIL FROM") {
            if buf.contains("<>") || buf.contains("ok@") {
                "250 OK\r\n".to_string()
            } else {
                "552-I do not\r\n552 like that MAIL FROM.\r\n".to_string()
            }
        } else if buf.starts_with("RCPT TO") {
            if buf.contains("ok") {
                "250 OK\r\n".to_string()
            } else {
                "550-I refuse to\r\n550 accept that recipient.\r\n".to_string()
            }
        } else if buf.starts_with("VRFY") {
            if buf.contains("ok") {
                format!("250 {}\r\n", buf.split_once(' ').unwrap().1)
            } else {
                "550-I refuse to\r\n550 verify that recipient.\r\n".to_string()
            }
        } else if buf.starts_with("EXPN") {
            if buf.contains("ok") {
                let parts = buf
                    .split_once(' ')
                    .unwrap()
                    .1
                    .split(',')
                    .filter_map(|s| {
                        if !s.is_empty() {
                            s.to_string().into()
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let mut buf = String::with_capacity(16);
                for (pos, part) in parts.iter().enumerate() {
                    buf.push_str("250");
                    buf.push(if pos == parts.len() - 1 { ' ' } else { '-' });
                    buf.push_str(part);
                    buf.push_str("\r\n");
                }

                buf
            } else {
                "550-I refuse to\r\n550 accept that recipient.\r\n".to_string()
            }
        } else if buf.starts_with("AUTH PLAIN") {
            let buf = base64_decode(buf.rsplit_once(' ').unwrap().1.as_bytes()).unwrap();
            if String::from_utf8_lossy(&buf).contains("ok") {
                "235 Great success!\r\n".to_string()
            } else {
                "535 No soup for you\r\n".to_string()
            }
        } else if buf.starts_with("QUIT") {
            "250 Arrivederci!\r\n".to_string()
        } else if buf.starts_with("RSET") {
            "250 Your wish is my command.\r\n".to_string()
        } else {
            panic!("Unknown command: {}", buf.trim());
        };
        //print!("<- {}", response);
        stream.write_all(response.as_bytes()).await.unwrap();

        if buf.contains("bye") || buf.starts_with("QUIT") {
            return;
        }
    }
}
