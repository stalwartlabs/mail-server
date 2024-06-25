/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use super::{AssertResult, ImapConnection, Type};

pub async fn test(_imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running COPY/MOVE tests...");

    // Check status
    imap_check
        .send("LIST \"\" % RETURN (STATUS (UIDNEXT MESSAGES UNSEEN SIZE RECENT))")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\"INBOX\" (UIDNEXT 11 MESSAGES 10 UNSEEN 10 SIZE 12193 RECENT 0)");

    // Select INBOX
    imap_check.send("SELECT INBOX").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Copying to the same mailbox should fail
    imap_check.send("COPY 1:* INBOX").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("CANNOT");

    // Copying to a non-existent mailbox should fail
    imap_check.send("COPY 1:* \"/dev/null\"").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TRYCREATE");

    // Create test folders
    imap_check.send("CREATE \"Scamorza Affumicata\"").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("CREATE \"Burrata al Tartufo\"").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Copy messages
    imap_check
        .send("COPY 1,3,5,7 \"Scamorza Affumicata\"")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("COPYUID")
        .assert_contains("1:4");

    // Check status
    imap_check
        .send("STATUS \"Scamorza Affumicata\" (UIDNEXT MESSAGES UNSEEN SIZE RECENT)")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 4")
        //.assert_contains("RECENT 4")
        .assert_contains("UNSEEN 4")
        .assert_contains("UIDNEXT 5")
        .assert_contains("SIZE 5851");

    // Check \Recent flag
    /*imap_check.send("SELECT \"Scamorza Affumicata\"").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 4 RECENT");
    imap_check.send("FETCH 1:* (UID FLAGS)").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Recent", 4);
    imap_check.send("UNSELECT").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check
        .send("STATUS \"Scamorza Affumicata\" (UIDNEXT MESSAGES UNSEEN SIZE RECENT)")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGES 4")
        .assert_contains("RECENT 0")
        .assert_contains("UNSEEN 4")
        .assert_contains("UIDNEXT 5")
        .assert_contains("SIZE 5851");
    imap_check.send("SELECT \"Scamorza Affumicata\"").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 0 RECENT");
    imap_check.send("FETCH 1:* (UID FLAGS)").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Recent", 0);*/

    // Move all messages to Burrata
    imap_check.send("SELECT \"Scamorza Affumicata\"").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("MOVE 1:* \"Burrata al Tartufo\"").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* OK [COPYUID")
        .assert_contains("1:4")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE");

    // Check status
    imap_check
        .send("LIST \"\" % RETURN (STATUS (UIDNEXT MESSAGES UNSEEN SIZE))")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\"Burrata al Tartufo\" (UIDNEXT 5 MESSAGES 4 UNSEEN 4 SIZE 5851)")
        .assert_contains("\"Scamorza Affumicata\" (UIDNEXT 5 MESSAGES 0 UNSEEN 0 SIZE 0)")
        .assert_contains("\"INBOX\" (UIDNEXT 11 MESSAGES 10 UNSEEN 10 SIZE 12193)");

    // Move the messages back to Scamorza, UIDNEXT should increase.
    imap_check.send("SELECT \"Burrata al Tartufo\"").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap_check.send("MOVE 1:* \"Scamorza Affumicata\"").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* OK [COPYUID")
        .assert_contains("5:8")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE")
        .assert_contains("* 1 EXPUNGE");

    // Check status
    imap_check
        .send("LIST \"\" % RETURN (STATUS (UIDNEXT MESSAGES UNSEEN SIZE))")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\"Burrata al Tartufo\" (UIDNEXT 5 MESSAGES 0 UNSEEN 0 SIZE 0)")
        .assert_contains("\"Scamorza Affumicata\" (UIDNEXT 9 MESSAGES 4 UNSEEN 4 SIZE 5851)")
        .assert_contains("\"INBOX\" (UIDNEXT 11 MESSAGES 10 UNSEEN 10 SIZE 12193)");
}
