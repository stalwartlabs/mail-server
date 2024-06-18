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

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use ahash::AHashSet;
use common::{
    config::smtp::session::{Milter, MilterVersion, Stage},
    expr::if_block::IfBlock,
    manager::webadmin::Resource,
    Core,
};
use hyper::{body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jmap::api::http::{fetch_body, ToHttpResponse};
use mail_auth::AuthenticatedMessage;
use mail_parser::MessageParser;
use serde::Deserialize;
use smtp::{
    core::{Inner, Session, SessionData},
    inbound::{
        jmilter::{self, Request, SmtpResponse},
        milter::{
            receiver::{FrameResult, Receiver},
            Action, Command, Macros, MilterClient, Modification, Options, Response,
        },
    },
};
use store::Stores;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use utils::config::Config;

use crate::smtp::{
    build_smtp,
    inbound::TestMessage,
    session::{load_test_message, TestSession, VerifyResponse},
    TempDir, TestSMTP,
};

#[derive(Debug, Deserialize)]
struct HeaderTest {
    modifications: Vec<Modification>,
    result: String,
}

const CONFIG_MILTER: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

[session.rcpt]
relay = true

[[session.milter]]
hostname = "127.0.0.1"
port = 9332
#port = 11332
#port = 7357
enable = true
options.version = 6
tls = false
stages = ["data"]

"#;

const CONFIG_JMILTER: &str = r#"
[storage]
data = "sqlite"
lookup = "sqlite"
blob = "sqlite"
fts = "sqlite"

[store."sqlite"]
type = "sqlite"
path = "{TMP}/queue.db"

[session.rcpt]
relay = true

[[session.jmilter]]
url = "http://127.0.0.1:9333"
enable = true
stages = ["data"]
"#;

#[tokio::test]
async fn milter_session() {
    // Enable logging
    /*let disable = "true";
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Configure tests
    let tmp_dir = TempDir::new("smtp_milter_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG_MILTER)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let _rx = spawn_mock_milter_server();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut inner = Inner::default();
    let mut qr = inner.init_test_queue(&core);

    // Build session
    let mut session = Session::test(build_smtp(core, inner));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.doe.org").await;

    // Test reject
    session
        .send_message(
            "reject@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "503 5.5.3",
        )
        .await;
    qr.assert_no_events();

    // Test discard
    session
        .send_message(
            "discard@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.assert_no_events();

    // Test temp fail
    session
        .send_message(
            "temp_fail@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "451 4.3.5",
        )
        .await;
    qr.assert_no_events();

    // Test shutdown
    session
        .send_message(
            "shutdown@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "421 4.3.0",
        )
        .await;
    qr.assert_no_events();

    // Test reply code
    session
        .send_message(
            "reply_code@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "321",
        )
        .await;
    qr.assert_no_events();

    // Test accept with header addition
    session
        .send_message(
            "0@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-Hello: World")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Are you hungry yet?");

    // Test accept with header replacement
    session
        .send_message(
            "3@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("Subject: [SPAM] Saying Hello")
        .assert_count("References: ", 1)
        .assert_contains("Are you hungry yet?");

    // Test accept with body replacement
    session
        .send_message(
            "2@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-Spam: Yes")
        .assert_contains("123456");
}

#[tokio::test]
async fn jmilter_session() {
    // Enable logging
    /*let disable = "true";
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    )
    .unwrap();*/

    // Configure tests
    let tmp_dir = TempDir::new("smtp_jmilter_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG_JMILTER)).unwrap();
    let stores = Stores::parse_all(&mut config).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let _rx = spawn_mock_jmilter_server();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut inner = Inner::default();
    let mut qr = inner.init_test_queue(&core);

    // Build session
    let mut session = Session::test(build_smtp(core, inner));
    session.data.remote_ip_str = "10.0.0.1".to_string();
    session.eval_session_params().await;
    session.ehlo("mx.doe.org").await;

    // Test reject
    session
        .send_message(
            "reject@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "503 5.5.3",
        )
        .await;
    qr.assert_no_events();

    // Test discard
    session
        .send_message(
            "discard@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.assert_no_events();

    // Test temp fail
    session
        .send_message(
            "temp_fail@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "451 4.3.5",
        )
        .await;
    qr.assert_no_events();

    // Test shutdown
    session
        .send_message(
            "shutdown@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "421 4.3.0",
        )
        .await;
    qr.assert_no_events();

    // Test reply code
    session
        .send_message(
            "reply_code@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "321",
        )
        .await;
    qr.assert_no_events();

    // Test accept with header addition
    session
        .send_message(
            "0@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-Hello: World")
        .assert_contains("Subject: Is dinner ready?")
        .assert_contains("Are you hungry yet?");

    // Test accept with header replacement
    session
        .send_message(
            "3@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("Subject: [SPAM] Saying Hello")
        .assert_count("References: ", 1)
        .assert_contains("Are you hungry yet?");

    // Test accept with body replacement
    session
        .send_message(
            "2@doe.org",
            &["bill@foobar.org"],
            "test:no_dkim",
            "250 2.0.0",
        )
        .await;
    qr.expect_message()
        .await
        .read_lines(&qr)
        .await
        .assert_contains("X-Spam: Yes")
        .assert_contains("123456");
}

#[test]
fn milter_address_modifications() {
    let test_message = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("smtp")
            .join("milter")
            .join("message.eml"),
    )
    .unwrap();
    let parsed_test_message = AuthenticatedMessage::parse(test_message.as_bytes()).unwrap();

    let mut data = SessionData::new(
        "127.0.0.1".parse().unwrap(),
        0,
        "127.0.0.1".parse().unwrap(),
        0,
    );

    // ChangeFrom
    assert!(data
        .apply_milter_modifications(
            vec![Modification::ChangeFrom {
                sender: "<>".to_string(),
                args: String::new()
            }],
            &parsed_test_message
        )
        .is_none());
    let addr = data.mail_from.as_ref().unwrap();
    assert_eq!(addr.address_lcase, "");
    assert_eq!(addr.dsn_info, None);
    assert_eq!(addr.flags, 0);

    // ChangeFrom with parameters
    assert!(data
        .apply_milter_modifications(
            vec![Modification::ChangeFrom {
                sender: "john@example.org".to_string(),
                args: "REQUIRETLS ENVID=abc123".to_string(), //"NOTIFY=SUCCESS,FAILURE ENVID=abc123\n".to_string()
            }],
            &parsed_test_message
        )
        .is_none());
    let addr = data.mail_from.as_ref().unwrap();
    assert_eq!(addr.address_lcase, "john@example.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("abc123".to_string()));

    // Add recipients
    assert!(data
        .apply_milter_modifications(
            vec![
                Modification::AddRcpt {
                    recipient: "bill@example.org".to_string(),
                    args: "".to_string(),
                },
                Modification::AddRcpt {
                    recipient: "jane@foobar.org".to_string(),
                    args: "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;Jane.Doe@Foobar.org".to_string(),
                },
                Modification::AddRcpt {
                    recipient: "<bill@example.org>".to_string(),
                    args: "".to_string(),
                },
                Modification::AddRcpt {
                    recipient: "<>".to_string(),
                    args: "".to_string(),
                },
            ],
            &parsed_test_message
        )
        .is_none());
    assert_eq!(data.rcpt_to.len(), 2);
    let addr = data.rcpt_to.first().unwrap();
    assert_eq!(addr.address_lcase, "bill@example.org");
    assert_eq!(addr.dsn_info, None);
    assert_eq!(addr.flags, 0);
    let addr = data.rcpt_to.last().unwrap();
    assert_eq!(addr.address_lcase, "jane@foobar.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("Jane.Doe@Foobar.org".to_string()));

    // Remove recipients
    assert!(data
        .apply_milter_modifications(
            vec![
                Modification::DeleteRcpt {
                    recipient: "bill@example.org".to_string(),
                },
                Modification::DeleteRcpt {
                    recipient: "<>".to_string(),
                },
            ],
            &parsed_test_message
        )
        .is_none());
    assert_eq!(data.rcpt_to.len(), 1);
    let addr = data.rcpt_to.last().unwrap();
    assert_eq!(addr.address_lcase, "jane@foobar.org");
    assert_ne!(addr.flags, 0);
    assert_eq!(addr.dsn_info, Some("Jane.Doe@Foobar.org".to_string()));
}

#[test]
fn milter_message_modifications() {
    // Read test message
    let milter_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("smtp")
        .join("milter");
    let test_message = fs::read_to_string(milter_path.join("message.eml")).unwrap();
    let tests = serde_json::from_str::<Vec<HeaderTest>>(
        &fs::read_to_string(milter_path.join("message.json")).unwrap(),
    )
    .unwrap();
    let parsed_test_message = AuthenticatedMessage::parse(test_message.as_bytes()).unwrap();
    let mut session_data = SessionData::new(
        "127.0.0.1".parse().unwrap(),
        0,
        "127.0.0.1".parse().unwrap(),
        0,
    );

    for test in tests {
        assert_eq!(
            test.result,
            String::from_utf8(
                session_data
                    .apply_milter_modifications(test.modifications, &parsed_test_message)
                    .unwrap()
            )
            .unwrap()
        )
    }
}

#[test]
fn milter_frame_receiver() {
    let mut stream = Vec::new();

    for i in 0u32..100u32 {
        stream.extend_from_slice((i + 1).to_be_bytes().as_ref());
        stream.push(i as u8);
        for v in 0..i {
            stream.push(v as u8);
        }
    }

    for chunk_size in [stream.len(), 1, 2, 3, 4, 10, 20, 30, 40, 100, 200, 300, 400] {
        let mut receiver = Receiver::with_max_frame_len(100);
        let mut frame_num = 0;

        'outer: for chunk in stream.chunks(chunk_size) {
            loop {
                match receiver.read_frame(chunk) {
                    FrameResult::Frame(bytes) => {
                        /*println!(
                            "frame {frame_num}, chunk: {chunk_size}, {}",
                            if matches!(bytes, std::borrow::Cow::Borrowed(_)) {
                                "borrowed"
                            } else {
                                "owned"
                            }
                        );*/
                        assert_eq!(*bytes.first().unwrap(), frame_num);
                        assert_eq!(bytes.len(), frame_num as usize + 1);
                        frame_num += 1;
                    }
                    FrameResult::Incomplete => continue 'outer,
                    FrameResult::TooLarge(size) => {
                        panic!("Frame too large: {size}")
                    }
                }
            }
        }

        assert_eq!(frame_num, 100, "chunk_size: {}", chunk_size);
    }
}

#[tokio::test]
#[ignore]
async fn milter_client_test() {
    //const PORT : u16 = 11332;
    const PORT: u16 = 7357;
    let mut client = MilterClient::connect(
        &Milter {
            enable: IfBlock::empty(""),
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], PORT))],
            hostname: "localhost".to_string(),
            port: PORT,
            timeout_connect: Duration::from_secs(10),
            timeout_command: Duration::from_secs(30),
            timeout_data: Duration::from_secs(30),
            tls: false,
            tls_allow_invalid_certs: false,
            tempfail_on_error: false,
            max_frame_len: 5000000,
            protocol_version: MilterVersion::V6,
            flags_actions: None,
            flags_protocol: None,
            run_on_stage: AHashSet::from([Stage::Data]),
        },
        tracing::span!(tracing::Level::TRACE, "hi"),
    )
    .await
    .unwrap();
    client.init().await.unwrap();

    let raw_message = load_test_message("arc", "messages");
    let message = MessageParser::new().parse(raw_message.as_bytes()).unwrap();

    let r = client
        .connection(
            "gmail.com",
            "127.0.0.1".parse().unwrap(),
            1235,
            Macros::new(),
        )
        .await
        .unwrap();
    println!("CONNECT: {:?}", r);
    let r = client
        .mail_from("john@gmail.com", None::<&[&str]>, Macros::new())
        .await
        .unwrap();
    println!("MAIL FROM: {:?}", r);
    let r = client
        .rcpt_to("user@gmail.com", None::<&[&str]>, Macros::new())
        .await
        .unwrap();
    println!("RCPT TO: {:?}", r);

    let r = client.data().await.unwrap();
    println!("DATA: {:?}", r);
    let r = client.headers(message.headers_raw()).await.unwrap();
    println!("HEADERS: {:?}", r);
    let r = client
        .body(&message.raw_message()[message.root_part().raw_body_offset()..])
        .await
        .unwrap();
    println!("BODY: {:?}", r);

    client.quit().await.unwrap();
}

pub fn spawn_mock_milter_server() -> watch::Sender<bool> {
    let (tx, rx) = watch::channel(true);
    let tests = Arc::new(
        serde_json::from_str::<Vec<HeaderTest>>(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("smtp")
                    .join("milter")
                    .join("message.json"),
            )
            .unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9332")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Milter server to 127.0.0.1:9332: {e}");
            });
        let mut rx_ = rx.clone();
        //println!("Mock Milter server listening on port 9332");
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            tokio::spawn(accept_milter(stream, rx.clone(), tests.clone()));
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    //println!("Mock Milter server stopping");
                    break;
                }
            };
        }
    });

    tx
}

async fn accept_milter(
    mut stream: TcpStream,
    mut rx: watch::Receiver<bool>,
    tests: Arc<Vec<HeaderTest>>,
) {
    let mut buf = vec![0u8; 1024];
    let mut receiver = Receiver::with_max_frame_len(5000000);
    let mut action = None;
    let mut modifications = None;

    'outer: loop {
        let br = tokio::select! {
            br = stream.read(&mut buf) => {
                match br {
                    Ok(br) => {
                        br
                    }
                    Err(_) => {
                        break;
                    }
                }
            },
            _ = rx.changed() => {
                break;
            }
        };

        if br == 0 {
            break;
        }

        loop {
            match receiver.read_frame(&buf[..br]) {
                FrameResult::Frame(bytes) => {
                    let cmd = Command::deserialize(bytes.as_ref());
                    println!("CMD: {cmd}");

                    let response = match cmd {
                        Command::Abort | Command::Macro { .. } => continue,
                        Command::Body { .. }
                        | Command::Data
                        | Command::Connect { .. }
                        | Command::Header { .. }
                        | Command::Helo { .. }
                        | Command::Rcpt { .. }
                        | Command::QuitNewConnection
                        | Command::EndOfHeader => Response::Action(Action::Accept),
                        Command::OptionNegotiation(_) => Response::OptionNegotiation(Options {
                            version: 6,
                            actions: 0,
                            protocol: 0,
                        }),
                        Command::MailFrom { sender, .. } => {
                            let sender = std::str::from_utf8(sender).unwrap();
                            action = match sender
                                .strip_prefix('<')
                                .unwrap()
                                .split_once('@')
                                .unwrap()
                                .0
                            {
                                "accept" => Action::Accept,
                                "reject" => Action::Reject,
                                "discard" => Action::Discard,
                                "temp_fail" => Action::TempFail,
                                "shutdown" => Action::Shutdown,
                                "conn_fail" => Action::ConnectionFailure,
                                "reply_code" => Action::ReplyCode {
                                    code: [b'3', b'2', b'1'],
                                    text: "test".to_string(),
                                },
                                test_num => {
                                    modifications = tests[test_num.parse::<usize>().unwrap()]
                                        .modifications
                                        .clone()
                                        .into();
                                    Action::Accept
                                }
                            }
                            .into();
                            Response::Action(Action::Accept)
                        }
                        Command::Quit => break 'outer,
                        Command::EndOfBody => {
                            if let Some(modifications) = modifications.take() {
                                for modification in modifications {
                                    // Write modifications
                                    stream
                                        .write_all(
                                            &Response::Modification(modification).serialize(),
                                        )
                                        .await
                                        .unwrap();
                                }
                            }

                            Response::Action(action.take().unwrap())
                        }
                    };

                    // Write response
                    stream.write_all(&response.serialize()).await.unwrap();
                }
                FrameResult::Incomplete => continue 'outer,
                FrameResult::TooLarge(size) => {
                    panic!("Frame too large: {size}")
                }
            }
        }
    }
}

pub fn spawn_mock_jmilter_server() -> watch::Sender<bool> {
    let (tx, rx) = watch::channel(true);
    let tests = Arc::new(
        serde_json::from_str::<Vec<HeaderTest>>(
            &fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("resources")
                    .join("smtp")
                    .join("milter")
                    .join("message.json"),
            )
            .unwrap(),
        )
        .unwrap(),
    );

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9333")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Milter server to 127.0.0.1:9333: {e}");
            });
        let mut rx_ = rx.clone();
        //println!("Mock jMilter server listening on port 9333");
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {

                            let _ = http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|mut req: hyper::Request<body::Incoming>| {
                                    let tests = tests.clone();

                                    async move {

                                        let request = serde_json::from_slice::<Request>(&fetch_body(&mut req, 1024 * 1024).await.unwrap())
                                        .unwrap();
                                        let response = handle_jmilter(request, tests);

                                        Ok::<_, hyper::Error>(
                                            Resource {
                                                content_type: "application/json",
                                                contents: serde_json::to_string(&response).unwrap().into_bytes(),
                                            }
                                            .into_http_response(),
                                        )
                                    }
                                }),
                            )
                            .await;
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    //println!("Mock jMilter server stopping");
                    break;
                }
            };
        }
    });

    tx
}

fn handle_jmilter(request: Request, tests: Arc<Vec<HeaderTest>>) -> jmilter::Response {
    match request
        .envelope
        .unwrap()
        .from
        .address
        .split_once('@')
        .unwrap()
        .0
    {
        "accept" => jmilter::Response {
            action: jmilter::Action::Accept,
            response: None,
            modifications: vec![],
        },
        "reject" => jmilter::Response {
            action: jmilter::Action::Reject,
            response: None,
            modifications: vec![],
        },
        "discard" => jmilter::Response {
            action: jmilter::Action::Discard,
            response: None,
            modifications: vec![],
        },
        "temp_fail" => jmilter::Response {
            action: jmilter::Action::Reject,
            response: SmtpResponse {
                status: 451.into(),
                enhanced_status: "4.3.5".to_string().into(),
                message: "Unable to accept message at this time.".to_string().into(),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        "shutdown" => jmilter::Response {
            action: jmilter::Action::Reject,
            response: SmtpResponse {
                status: 421.into(),
                enhanced_status: "4.3.0".to_string().into(),
                message: "Server shutting down".to_string().into(),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        "conn_fail" => jmilter::Response {
            action: jmilter::Action::Accept,
            response: SmtpResponse {
                disconnect: true,
                ..Default::default()
            }
            .into(),
            modifications: vec![],
        },
        "reply_code" => jmilter::Response {
            action: jmilter::Action::Reject,
            response: SmtpResponse {
                status: 321.into(),
                enhanced_status: "3.1.1".to_string().into(),
                message: "Test".to_string().into(),
                disconnect: false,
            }
            .into(),
            modifications: vec![],
        },
        test_num => jmilter::Response {
            action: jmilter::Action::Accept,
            response: None,
            modifications: tests[test_num.parse::<usize>().unwrap()]
                .modifications
                .iter()
                .map(|m| match m {
                    Modification::ChangeFrom { sender, args } => {
                        jmilter::Modification::ChangeFrom {
                            value: sender.clone(),
                            parameters: args
                                .split_whitespace()
                                .map(|arg| {
                                    let (key, value) = arg.split_once('=').unwrap();
                                    (key.to_string(), Some(value.to_string()))
                                })
                                .collect(),
                        }
                    }
                    Modification::AddRcpt { recipient, args } => {
                        jmilter::Modification::AddRecipient {
                            value: recipient.clone(),
                            parameters: args
                                .split_whitespace()
                                .map(|arg| {
                                    let (key, value) = arg.split_once('=').unwrap();
                                    (key.to_string(), Some(value.to_string()))
                                })
                                .collect(),
                        }
                    }
                    Modification::DeleteRcpt { recipient } => {
                        jmilter::Modification::DeleteRecipient {
                            value: recipient.clone(),
                        }
                    }
                    Modification::ReplaceBody { value } => jmilter::Modification::ReplaceContents {
                        value: String::from_utf8(value.clone()).unwrap(),
                    },
                    Modification::AddHeader { name, value } => jmilter::Modification::AddHeader {
                        name: name.clone(),
                        value: value.clone(),
                    },
                    Modification::InsertHeader { index, name, value } => {
                        jmilter::Modification::InsertHeader {
                            index: *index,
                            name: name.clone(),
                            value: value.clone(),
                        }
                    }
                    Modification::ChangeHeader { index, name, value } => {
                        jmilter::Modification::ChangeHeader {
                            index: *index,
                            name: name.clone(),
                            value: value.clone(),
                        }
                    }
                    Modification::Quarantine { reason } => jmilter::Modification::AddHeader {
                        name: "X-Quarantine".to_string(),
                        value: reason.to_string(),
                    },
                })
                .collect(),
        },
    }
}
