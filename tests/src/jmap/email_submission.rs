/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use directory::backend::internal::manage::ManageDirectory;
use jmap_client::{
    core::set::{SetError, SetErrorType, SetObject},
    email_submission::{query::Filter, Address, Delivered, DeliveryStatus, Displayed, UndoStatus},
    mailbox::Role,
    Error,
};
use jmap_proto::types::id::Id;
use mail_parser::DateTime;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::parking_lot::Mutex;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::mpsc,
};

use crate::jmap::{
    assert_is_empty, email_set::assert_email_properties, mailbox::destroy_all_mailboxes,
};

use super::JMAPTest;

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

#[allow(clippy::disallowed_types)]
pub async fn test(params: &mut JMAPTest) {
    println!("Running E-mail submissions tests...");
    // Start mock SMTP server
    let server = params.server.clone();
    let client = &mut params.client;
    let (mut smtp_rx, smtp_settings) = spawn_mock_smtp_server();
    server.core.smtp.resolvers.dns.ipv4_add(
        "localhost",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + std::time::Duration::from_secs(10),
    );

    // Create a test account
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    params
        .directory
        .link_test_address("jdoe@example.com", "john.doe@example.com", "alias")
        .await;
    let account_id = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    )
    .to_string();

    // Test automatic identity creation
    for (identity_id, email) in [(0u64, "jdoe@example.com"), (1u64, "john.doe@example.com")] {
        let identity = client
            .identity_get(&Id::from(identity_id).to_string(), None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.email().unwrap(), email);
        assert_eq!(identity.name().unwrap(), format!("John Doe <{email}>"));
    }

    // Create an identity without using a valid address should fail
    match client
        .set_default_account_id(&account_id)
        .identity_create("John Doe", "someaddress@domain.com")
        .await
        .unwrap_err()
    {
        Error::Set(err) => assert_eq!(err.error(), &SetErrorType::InvalidProperties),
        err => panic!("Unexpected error: {:?}", err),
    }

    // Create an identity
    let identity_id = client
        .identity_create("John Doe (manually created)", "jdoe@example.com")
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
            type_: SetErrorType::NoRecipients,
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
            type_: SetErrorType::ForbiddenFrom,
            ..
        }))
    ));

    // Submit a valid message submission
    let email_body =
        "From: jdoe@example.com\r\nTo: jane_smith@remote.org\r\nSubject: hey\r\n\r\ntest";
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
            ["<jane_smith@remote.org>"],
            email_body,
        ),
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

    for _ in 0..3 {
        let mut message = expect_message_delivery(&mut smtp_rx).await;

        assert_eq!(message.mail_from, "<jdoe@example.com>");
        let rcpt_to = message.rcpt_to.pop().unwrap();
        assert!([
            "<james@other_domain.com>",
            "<secret_rcpt@test.com>",
            "<tim@foobar.com>",
        ]
        .contains(&rcpt_to.as_str()));

        assert!(
            message.message.contains(email_body),
            "Got [{}], Expected[{}]",
            message.message,
            email_body
        );
    }

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
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
            (
                "secret_rcpt@test.com".to_string(),
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
            (
                "james@other_domain.com".to_string(),
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
        ])
    );

    // SMTP rejects some of the recipients
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            "jdoe@example.com",
            [
                "nonexistant@example.com",
                "delay@other_domain.com",
                "fail@test.com",
                "tim@foobar.com",
            ],
        )
        .await
        .unwrap()
        .take_id();
    assert_message_delivery(
        &mut smtp_rx,
        MockMessage::new("<jdoe@example.com>", ["<tim@foobar.com>"], email_body),
    )
    .await;
    expect_nothing(&mut smtp_rx).await;

    // Verify SMTP replies
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        email_submission.undo_status().unwrap(),
        &UndoStatus::Pending
    );
    assert_eq!(
        email_submission.delivery_status().unwrap(),
        &AHashMap::from_iter([
            (
                "nonexistant@example.com".to_string(),
                DeliveryStatus::new(
                    "550 5.1.2 Mailbox does not exist.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "delay@other_domain.com".to_string(),
                DeliveryStatus::new(
                    "Code: 451, Enhanced code: 4.5.3, Message: Try again later.",
                    Delivered::Queued,
                    Displayed::Unknown
                )
            ),
            (
                "fail@test.com".to_string(),
                DeliveryStatus::new(
                    "Code: 550, Enhanced code: 0.0.0, Message: I refuse to accept that recipient.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "tim@foobar.com".to_string(),
                DeliveryStatus::new(
                    "Code: 250, Enhanced code: 0.0.0, Message: OK",
                    Delivered::Yes,
                    Displayed::Unknown
                )
            ),
        ])
    );

    // Cancel submission
    client
        .email_submission_change_status(&email_submission_id, UndoStatus::Canceled)
        .await
        .unwrap();
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
                "nonexistant@example.com".to_string(),
                DeliveryStatus::new(
                    "550 5.1.2 Mailbox does not exist.",
                    Delivered::No,
                    Displayed::Unknown
                )
            ),
            (
                "delay@other_domain.com".to_string(),
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
            (
                "fail@test.com".to_string(),
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
            (
                "tim@foobar.com".to_string(),
                DeliveryStatus::new("250 2.1.5 Queued", Delivered::Unknown, Displayed::Unknown)
            ),
        ])
    );

    // Confirm that the sendAt property is updated when using FUTURERELEASE
    let hold_until = DateTime::parse_rfc3339("2079-11-20T05:00:00Z")
        .unwrap()
        .to_timestamp();
    let email_submission_id = client
        .email_submission_create_envelope(
            &email_id,
            &identity_id,
            Address::new("jdoe@example.com").parameter("HOLDUNTIL", Some(hold_until.to_string())),
            ["jane_smith@remote.org"],
        )
        .await
        .unwrap()
        .take_id();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let email_submission = client
        .email_submission_get(&email_submission_id, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(email_submission.send_at().unwrap(), hold_until);
    assert_eq!(
        email_submission.undo_status().unwrap(),
        &UndoStatus::Pending
    );
    assert_eq!(
        email_submission.delivery_status().unwrap(),
        &AHashMap::from_iter([(
            "jane_smith@remote.org".to_string(),
            DeliveryStatus::new("250 2.1.5 Queued", Delivered::Queued, Displayed::Unknown)
        ),])
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
    smtp_settings.lock().do_stop = true;

    // Destroy the created mailbox, identity and all submissions
    for identity_id in [
        identity_id,
        Id::from(0u64).to_string(),
        Id::from(1u64).to_string(),
    ] {
        client.identity_destroy(&identity_id).await.unwrap();
    }
    for id in client
        .email_submission_query(None::<Filter>, None::<Vec<_>>)
        .await
        .unwrap()
        .take_ids()
    {
        let _ = client
            .email_submission_change_status(&id, UndoStatus::Canceled)
            .await;
        client.email_submission_destroy(&id).await.unwrap();
    }
    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
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
                //print!("-> {}", buf);
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
                    if buf.contains("fail@") {
                        tx.write_all(
                            "550-I refuse to\r\n550 accept that recipient.\r\n".as_bytes(),
                        )
                        .await
                        .unwrap();
                    } else if buf.contains("delay@") {
                        tx.write_all("451 4.5.3 Try again later.\r\n".as_bytes())
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
                                message.message += buf.as_str();
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
                //println!("Mock SMTP server stopped.");
                break;
            }
        }
    });

    (event_rx, _settings)
}

pub async fn expect_message_delivery(event_rx: &mut mpsc::Receiver<MockMessage>) -> MockMessage {
    match tokio::time::timeout(Duration::from_millis(3000), event_rx.recv()).await {
        Ok(Some(message)) => {
            //println!("Got message [{}]", message.message);

            message
        }
        result => {
            panic!("Timeout waiting for message, got: {:?}", result);
        }
    }
}

pub async fn assert_message_delivery(
    event_rx: &mut mpsc::Receiver<MockMessage>,
    expected_message: MockMessage,
) {
    let message = expect_message_delivery(event_rx).await;

    assert_eq!(message.mail_from, expected_message.mail_from);
    assert_eq!(message.rcpt_to, expected_message.rcpt_to);

    if let Some(needle) = expected_message.message.strip_prefix('@') {
        assert!(
            message.message.contains(needle),
            "[{}] needle = {:?}",
            message.message,
            needle
        );
    } else {
        assert!(
            message.message.contains(&expected_message.message),
            "Got [{}], Expected[{}]",
            message.message,
            expected_message.message
        );
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
