/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use crate::jmap::wait_for_index;

use super::{AssertResult, IMAPTest, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection, handle: &IMAPTest) {
    println!("Running STORE tests...");

    // Select INBOX
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("10 EXISTS")
        .assert_contains("[UIDNEXT 11]");

    // Set all messages to flag "Seen"
    imap.send("UID STORE 1:10 +FLAGS.SILENT (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 0);

    // Check that the flags were set
    imap.send("UID FETCH 1:* (Flags)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Seen", 10);

    // Check status
    imap.send("STATUS INBOX (UIDNEXT MESSAGES UNSEEN)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 10")
        .assert_contains("UNSEEN 0")
        .assert_contains("UIDNEXT 11");

    // Remove Seen flag from all messages
    imap.send("UID STORE 1:10 -FLAGS (\\Seen)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 10)
        .assert_count("Seen", 0);

    // Check that the flags were removed
    imap.send("UID FETCH 1:* (Flags)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Seen", 0);
    imap.send("STATUS INBOX (UIDNEXT MESSAGES UNSEEN)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 10")
        .assert_contains("UNSEEN 10")
        .assert_contains("UIDNEXT 11");

    // Store using saved searches
    wait_for_index(&handle.jmap).await;
    imap.send("SEARCH RETURN (SAVE) FROM nathaniel").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID STORE $ +FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 3);

    // Remove Answered flag
    imap.send("UID STORE 1:* -FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FLAGS", 3)
        .assert_count("Answered", 0);
}
