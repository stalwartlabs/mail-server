use std::{sync::Arc, time::Duration};

use ahash::AHashMap;
use jmap::{JMAP, SUPERUSER_ID};
use jmap_client::{
    client::Client,
    core::set::{SetError, SetErrorType, SetObject},
    email_submission::{Address, Delivered, DeliveryStatus, Displayed, UndoStatus},
    mailbox::Role,
    Error,
};
use jmap_proto::types::id::Id;
use mail_parser::DateTime;
use store::parking_lot::Mutex;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};

use crate::jmap::email_set::assert_email_properties;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MockMessage {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
    pub message: String,
}

impl MockMessage {
    pub fn new<T, U>(mail_from: T, rcpt_to: U, message: T) -> Self
    where
        T: Into<String>,
        U: IntoIterator<Item = T>,
    {
        Self {
            mail_from: mail_from.into(),
            rcpt_to: rcpt_to.into_iter().map(|s| s.into()).collect(),
            message: message.into(),
        }
    }
}

#[derive(Default)]
pub struct MockSMTPSettings {
    pub fail_mail_from: bool,
    pub fail_rcpt_to: bool,
    pub fail_message: bool,
    pub do_stop: bool,
}

const TEST_DKIM_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

#[allow(clippy::disallowed_types)]
pub async fn test(server: Arc<JMAP>, client: &mut Client) {
    println!("Running E-mail submissions tests...");
    // Start mock SMTP server
    let (mut smtp_rx, smtp_settings) = spawn_mock_smtp_server();

    // Create an identity without using a valid address should fail
    match client
        .set_default_account_id(Id::new(1).to_string())
        .identity_create("John Doe", "jdoe@example.com")
        .await
        .unwrap_err()
    {
        Error::Set(err) => assert_eq!(err.error(), &SetErrorType::InvalidProperties),
        err => panic!("Unexpected error: {:?}", err),
    }

    // Create a domain and a test account
    let domain_id = client
        .set_default_account_id(Id::new(0))
        .domain_create("example.com")
        .await
        .unwrap()
        .take_id();
    let account_id = client
        .individual_create("jdoe@example.com", "12345", "John Doe")
        .await
        .unwrap()
        .take_id();
    let identity_id = client
        .set_default_account_id(&account_id)
        .identity_create("John Doe", "jdoe@example.com")
        .await
        .unwrap()
        .take_id();

    // Create test mailboxes
    let mailbox_id = client
        .mailbox_create("JMAP EmailSubmission", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let mailbox_id_2 = client
        .mailbox_create("JMAP EmailSubmission 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    // Import an email without any recipients
    let email_id = client
        .email_import(
            b"From: jdoe@example.com\nSubject: hey\n\ntest".to_vec(),
            [&mailbox_id],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();

    // Submission without a valid emailId or identityId should fail
    assert!(matches!(
        client
            .email_submission_create(Id::new(123456).to_string(), &identity_id)
            .await,
        Err(Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));
    assert!(matches!(
        client
            .email_submission_create(&email_id, Id::new(123456).to_string())
            .await,
        Err(Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));

    // Submissions of e-mails without any recipients should fail
    assert!(matches!(
        client
            .email_submission_create(&email_id, &identity_id)
            .await,
        Err(Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));

    // Submissions with an envelope that does not match
    // the identity from address should fail
    assert!(matches!(
        client
            .email_submission_create_envelope(
                &email_id,
                &identity_id,
                "other_address@example.com",
                Vec::<Address>::new(),
            )
            .await,
        Err(Error::Set(SetError {
            type_: SetErrorType::InvalidProperties,
            ..
        }))
    ));

    // Submit a valid message submission
    let email_body =
        "From: jdoe@example.com\r\nTo: jane_smith@example.com\r\nSubject: hey\r\n\r\ntest";
    let email_id = client
        .email_import(
            email_body.as_bytes().to_vec(),
            [&mailbox_id],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_id();
    client
        .email_submission_create(&email_id, &identity_id)
        .await
        .unwrap();

    // Confirm that the message has been delivered
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<jdoe@example.com>",
            ["<jane_smith@example.com>"],
            email_body,
        ),
        false,
    )
    .await;

    // Manually add recipients to the envelope and confirm submission
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            "jdoe@example.com",
            [
                "tim@foobar.com", // Should be de-duplicated
                "tim@foobar.com",
                "tim@foobar.com  ",
                " james@other_domain.com ", // Should be sanitized
                "  secret_rcpt@test.com  ",
            ],
        )
        .await
        .unwrap()
        .take_id();

    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<jdoe@example.com>",
            [
                "<james@other_domain.com>",
                "<secret_rcpt@test.com>",
                "<tim@foobar.com>",
            ],
            email_body,
        ),
        false,
    )
    .await;

    // Confirm that the email submission status was updated
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(email_submission.undo_status().unwrap(), &UndoStatus::Final);
    assert_eq!(
        email_submission.delivery_status().unwrap(),
        &AHashMap::from_iter([
            (
                "tim@foobar.com".to_string(),
                DeliveryStatus::new("250 OK", Delivered::Queued, Displayed::Unknown)
            ),
            (
                "secret_rcpt@test.com".to_string(),
                DeliveryStatus::new("250 OK", Delivered::Queued, Displayed::Unknown)
            ),
            (
                "james@other_domain.com".to_string(),
                DeliveryStatus::new("250 OK", Delivered::Queued, Displayed::Unknown)
            ),
        ])
    );

    // SMTP rejects some of the recipients
    smtp_settings.lock().fail_rcpt_to = true;
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            "jdoe@example.com",
            ["tim@foobar.com", "james@other_domain.com", "jane@test.com"],
        )
        .await
        .unwrap()
        .take_id();
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new("<jdoe@example.com>", ["<tim@foobar.com>"], email_body),
        false,
    )
    .await;

    // Confirm that all delivery failures were included
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(email_submission.undo_status().unwrap(), &UndoStatus::Final);
    assert_eq!(
        email_submission.delivery_status().unwrap(),
        &AHashMap::from_iter([
            (
                "james@other_domain.com".to_string(),
                DeliveryStatus::new(
                    "550 I refuse to accept that recipient.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "jane@test.com".to_string(),
                DeliveryStatus::new(
                    "550 I refuse to accept that recipient.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "tim@foobar.com".to_string(),
                DeliveryStatus::new("250 OK", Delivered::Queued, Displayed::Unknown)
            ),
        ])
    );
    smtp_settings.lock().fail_rcpt_to = false;

    // SMTP rejects the message
    smtp_settings.lock().fail_message = true;
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            "jdoe@example.com",
            ["tim@foobar.com", "james@other_domain.com", "jane@test.com"],
        )
        .await
        .unwrap()
        .take_id();
    expect_nothing(&mut smtp_rx).await;

    // Confirm that all delivery failures were included
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        email_submission.undo_status().unwrap(),
        &UndoStatus::Canceled
    );
    assert_eq!(
        email_submission.delivery_status().unwrap(),
        &AHashMap::from_iter([
            (
                "james@other_domain.com".to_string(),
                DeliveryStatus::new(
                    "503 Thank you but I am saving myself for dessert.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "jane@test.com".to_string(),
                DeliveryStatus::new(
                    "503 Thank you but I am saving myself for dessert.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "tim@foobar.com".to_string(),
                DeliveryStatus::new(
                    "503 Thank you but I am saving myself for dessert.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
        ])
    );
    smtp_settings.lock().fail_message = false;

    // Enable DKIM for the domain
    client
        .set_default_account_id(Id::from(SUPERUSER_ID))
        .domain_enable_dkim(&domain_id, TEST_DKIM_KEY, "my-selector", None)
        .await
        .unwrap();
    client.set_default_account_id(&account_id);

    // Confirm that the sendAt property is updated when using FUTURERELEASE
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            Address::new("jdoe@example.com").parameter("HOLDUNTIL", Some("2079-11-20T05:00:00Z")),
            ["jane_smith@example.com"],
        )
        .await
        .unwrap()
        .take_id();
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new(
            "<jdoe@example.com> HOLDUNTIL=2079-11-20T05:00:00Z",
            ["<jane_smith@example.com>"],
            email_body,
        ),
        true,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        email_submission.send_at().unwrap(),
        DateTime::parse_rfc3339("2079-11-20T05:00:00Z")
            .unwrap()
            .to_timestamp()
    );

    // Verify onSuccessUpdateEmail action
    let mut request = client.build();
    let set_request = request.set_email_submission();
    let create_id = set_request
        .create()
        .email_id(&email_id)
        .identity_id(&identity_id)
        .create_id()
        .unwrap();
    set_request
        .arguments()
        .on_success_update_email(&create_id)
        .keyword("$draft", true)
        .mailbox_id(&mailbox_id, false)
        .mailbox_id(&mailbox_id_2, true);
    request.send().await.unwrap().unwrap_method_responses();

    assert_email_properties(client, &email_id, &[&mailbox_id_2], &["$draft"]).await;

    // Verify onSuccessDestroyEmail action
    smtp_settings.lock().do_stop = true;
    let mut request = client.build();
    let set_request = request.set_email_submission();
    let create_id = set_request
        .create()
        .email_id(&email_id)
        .identity_id(&identity_id)
        .create_id()
        .unwrap();
    set_request.arguments().on_success_destroy_email(&create_id);
    request.send().await.unwrap().unwrap_method_responses();

    assert!(client
        .email_get(&email_id, None::<Vec<_>>)
        .await
        .unwrap()
        .is_none());

    // Destroy the created mailbox, identity and all submissions
    let todo = "true";
    /*client
        .set_default_account_id(Id::from(SUPERUSER_ID))
        .principal_destroy(&account_id)
        .await
        .unwrap();
    client.principal_destroy(&domain_id).await.unwrap();
    server.store.principal_purge().unwrap();
    server.store.assert_is_empty();*/
}

pub fn spawn_mock_smtp_server() -> (mpsc::Receiver<MockMessage>, Arc<Mutex<MockSMTPSettings>>) {
    // Create channels
    let (event_tx, event_rx) = mpsc::channel::<MockMessage>(100);
    let _settings = Arc::new(Mutex::new(MockSMTPSettings::default()));
    let settings = _settings.clone();

    // Start mock SMTP server
    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9999")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock SMTP server to 127.0.0.1:9999: {}", e);
            });

        while let Ok((mut stream, _)) = listener.accept().await {
            let (rx, mut tx) = stream.split();
            let mut rx = BufReader::new(rx);
            let mut buf = String::with_capacity(128);
            let mut message = MockMessage::default();

            tx.write_all(b"220 [127.0.0.1] Clueless host service ready\r\n")
                .await
                .unwrap();

            while rx.read_line(&mut buf).await.is_ok() {
                print!("-> {}", buf);
                if buf.starts_with("EHLO") {
                    tx.write_all(b"250 Hi there, but I have no extensions to offer :-(\r\n")
                        .await
                        .unwrap();
                } else if buf.starts_with("MAIL FROM") {
                    if settings.lock().fail_mail_from {
                        tx.write_all("552-I do not\r\n552 like that MAIL FROM.\r\n".as_bytes())
                            .await
                            .unwrap();
                    } else {
                        message.mail_from = buf.split_once(':').unwrap().1.trim().to_string();
                        tx.write_all(b"250 OK\r\n").await.unwrap();
                    }
                } else if buf.starts_with("RCPT TO") {
                    if settings.lock().fail_rcpt_to && !buf.contains("foobar.com") {
                        tx.write_all(
                            "550-I refuse to\r\n550 accept that recipient.\r\n".as_bytes(),
                        )
                        .await
                        .unwrap();
                    } else {
                        message
                            .rcpt_to
                            .push(buf.split(':').nth(1).unwrap().trim().to_string());
                        tx.write_all(b"250 OK\r\n").await.unwrap();
                    }
                } else if buf.starts_with("DATA") {
                    if settings.lock().fail_message {
                        tx.write_all(
                            "503-Thank you but I am\r\n503 saving myself for dessert.\r\n"
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    } else if !message.mail_from.is_empty() && !message.rcpt_to.is_empty() {
                        tx.write_all(b"354 Start feeding me now some quality content please\r\n")
                            .await
                            .unwrap();
                        buf.clear();
                        while rx.read_line(&mut buf).await.is_ok() {
                            if buf.starts_with('.') {
                                message.message = message.message.trim().to_string();
                                break;
                            } else {
                                message.message += &buf;
                                buf.clear();
                            }
                        }
                        tx.write_all(b"250 Great success!\r\n").await.unwrap();
                        message.rcpt_to.sort_unstable();
                        event_tx.send(message).await.unwrap();
                        message = MockMessage::default();
                    } else {
                        tx.write_all("554 You forgot to tell me a few things.\r\n".as_bytes())
                            .await
                            .unwrap();
                    }
                } else if buf.starts_with("QUIT") {
                    tx.write_all("250 Arrivederci!\r\n".as_bytes())
                        .await
                        .unwrap();
                    break;
                } else if buf.starts_with("RSET") {
                    tx.write_all("250 Your wish is my command.\r\n".as_bytes())
                        .await
                        .unwrap();
                    message = MockMessage::default();
                } else {
                    println!("Unknown command: {}", buf.trim());
                }
                buf.clear();
            }

            if settings.lock().do_stop {
                println!("Mock SMTP server stopped.");
                break;
            }
        }
    });

    (event_rx, _settings)
}

pub async fn assert_message_delivery(
    event_rx: &mut mpsc::Receiver<MockMessage>,
    expected_message: MockMessage,
    expect_dkim: bool,
) {
    match tokio::time::timeout(Duration::from_millis(3000), event_rx.recv()).await {
        Ok(Some(message)) => {
            assert_eq!(message.mail_from, expected_message.mail_from);
            assert_eq!(message.rcpt_to, expected_message.rcpt_to);

            println!("Got message [{}]", message.message);

            if let Some(needle) = expected_message.message.strip_prefix('@') {
                assert!(
                    message.message.contains(needle),
                    "[{}] needle = {:?}",
                    message.message,
                    needle
                );
            } else {
                let message = if expect_dkim {
                    if message.message.starts_with("DKIM-Signature:") {
                        message.message.split_once('\n').unwrap().1
                    } else {
                        panic!(
                            "Expected DKIM-Signature header but got: {}",
                            message.message
                        );
                    }
                } else {
                    &message.message
                };

                assert_eq!(message, expected_message.message);
            }
        }
        result => {
            panic!(
                "Timeout waiting for message {:?}: {:?}",
                expected_message, result
            );
        }
    }
}

pub async fn expect_nothing(event_rx: &mut mpsc::Receiver<MockMessage>) {
    match tokio::time::timeout(Duration::from_millis(500), event_rx.recv()).await {
        Err(_) => {}
        message => {
            panic!("Received a message when expecting nothing: {:?}", message);
        }
    }
}
