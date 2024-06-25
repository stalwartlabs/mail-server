/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use super::{AssertResult, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running SEARCH tests...");

    // Searches without selecting a mailbox should fail.
    imap.send("SEARCH RETURN (MIN MAX COUNT ALL) ALL").await;
    imap.assert_read(Type::Tagged, ResponseType::Bad).await;

    // Select INBOX
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("10 EXISTS")
        .assert_contains("[UIDNEXT 11]");
    imap_check.send("SELECT INBOX").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Min, Max and Count
    imap.send("SEARCH RETURN (MIN MAX COUNT ALL) ALL").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("COUNT 10 MIN 1 MAX 10 ALL 1,10");
    imap_check.send("UID SEARCH ALL").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 1 2 3 4 5 6 7 8 9 10");

    // Filters
    imap_check
        .send("UID SEARCH OR FROM nathaniel SUBJECT argentina")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 1 3 4 6");

    imap_check
        .send("UID SEARCH UNSEEN OR KEYWORD Flag_007 KEYWORD Flag_004")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 5 8");

    imap_check
        .send("UID SEARCH TEXT coffee FROM vandelay SUBJECT exporting SENTON 20-Nov-2021")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 10");

    imap_check
        .send("UID SEARCH NOT (FROM nathaniel ANSWERED)")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 2 3 5 7 8 9 10");

    imap_check
        .send("UID SEARCH UID 0:6 LARGER 1000 SMALLER 2000")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 1 2");

    // Saved search
    imap_check.send(
        "UID SEARCH RETURN (SAVE ALL) OR OR FROM nathaniel FROM vandelay OR SUBJECT rfc FROM gore",
    )
    .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("1,3:4,6,8,10");

    imap_check.send("UID SEARCH NOT $").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 2 5 7 9");

    imap_check
        .send("UID SEARCH $ SMALLER 1000 SUBJECT section")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SEARCH 8");

    imap_check.send("UID SEARCH RETURN (MIN MAX) NOT $").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MIN 2 MAX 9");

    // Sort
    imap_check
        .send("UID SORT (REVERSE SUBJECT REVERSE DATE) UTF-8 FROM Nathaniel")
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_equals("* SORT 6 4 1");

    imap.send("UID SORT RETURN (COUNT ALL) (DATE SUBJECT) UTF-8 ALL")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("COUNT 10 ALL 6,4:5,1,10,9,3,7:8,2");
}
