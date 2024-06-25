/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use crate::jmap::delivery::SmtpConnection;

use super::{AssertResult, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running IDLE tests...");

    // Switch connection to IDLE mode
    imap_check.send("CREATE Parmeggiano").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("SELECT Parmeggiano").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("NOOP").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("IDLE").await;
    imap_check
        .assert_read(Type::Continuation, ResponseType::Ok)
        .await;

    // Expect a new mailbox update
    imap.send("CREATE Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("LIST () \"/\" \"Provolone\"");

    // Insert a message in the new folder and expect an update
    let message = "From: test@domain.com\nSubject: Test\n\nTest message\n";
    imap.send(&format!("APPEND Provolone {{{}}}", message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 1")
        .assert_contains("UIDNEXT 2");

    // Change message to Seen and expect an update
    imap.send("SELECT Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("STORE 1:* +FLAGS (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 2");

    // Delete message and expect an update
    imap.send("STORE 1:* +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("CLOSE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"Provolone\"")
        .assert_contains("MESSAGES 0")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 2");

    // Delete folder and expect an update
    imap.send("DELETE Provolone").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("LIST (\\NonExistent) \"/\" \"Provolone\"");

    // Add a message to Inbox and expect an update
    imap.send(&format!("APPEND Parmeggiano {{{}}}", message.len()))
        .await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged(message).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 1")
        .assert_contains("UNSEEN 1");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXISTS");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (FLAGS () UID 1)");

    // Delete message and expect an update
    imap.send("SELECT Parmeggiano").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap.send("STORE 1 +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (FLAGS (\\Deleted) UID 1)");

    imap.send("UID EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 0 EXISTS");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 0")
        .assert_contains("UNSEEN 0");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 1 EXPUNGE");
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("* 0 EXISTS");

    // Test SMTP delivery notifications
    let mut lmtp = SmtpConnection::connect_port(11201).await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "X-Spam-Status: No\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    imap_check
        .assert_read(Type::Status, ResponseType::Ok)
        .await
        .assert_contains("STATUS \"INBOX\"")
        .assert_contains("MESSAGES 11");

    // Stop IDLE mode
    imap_check.send_raw("DONE").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap_check.send("NOOP").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
}
