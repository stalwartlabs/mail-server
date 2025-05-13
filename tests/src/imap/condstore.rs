/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use crate::imap::{
    append::{assert_append_message, build_messages},
    AssertResult,
};

use super::{ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running CONDSTORE...");

    // Test CONDSTORE parameter
    imap.send("SELECT INBOX (CONDSTORE)").await;
    let hms = imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .into_highest_modseq();

    // Unselect
    imap.send("UNSELECT").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Create test folders
    imap.send("CREATE Pecorino").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Enable CONDSTORE and QRESYNC
    imap.send("ENABLE CONDSTORE QRESYNC").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Make sure modseq did not change after creating a mailbox
    imap.send("SELECT Pecorino").await;
    assert_eq!(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
        hms
    );
    imap_check.send("LIST \"\" \"*\"").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("SELECT Pecorino (CONDSTORE)").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;

    // SEQ 0: Init
    let mut messages = build_messages();
    let mut modseqs = vec![hms];

    // SEQ 1: Append a message and make sure the modseq increased
    assert_append_message(imap, "Pecorino", &messages.pop().unwrap(), ResponseType::Ok).await;
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );
    assert_ne!(modseqs[modseqs.len() - 1], modseqs[modseqs.len() - 2]);

    // SEQ 2: Move out the message and make sure the modseq increased
    imap.send("UID MOVE 1 \"Deleted Items\"").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* VANISHED 1");
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );
    assert_ne!(modseqs[modseqs.len() - 1], modseqs[modseqs.len() - 2]);

    // SEQ 3: Insert message
    assert_append_message(imap, "Pecorino", &messages.pop().unwrap(), ResponseType::Ok).await;
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );

    // SEQ 4: Insert message
    assert_append_message(imap, "Pecorino", &messages.pop().unwrap(), ResponseType::Ok).await;
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );

    // SEQ 5: Insert message
    assert_append_message(imap, "Pecorino", &messages.pop().unwrap(), ResponseType::Ok).await;
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );

    // SEQ 6: Change a message flag
    imap.send("UID STORE 4 +FLAGS.SILENT (\\Answered)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_modseq(),
    );

    // SEQ 7: Insert message
    assert_append_message(imap, "Pecorino", &messages.pop().unwrap(), ResponseType::Ok).await;
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );

    // SEQ 8: Delete a message
    imap.send("UID STORE 2 +FLAGS.SILENT (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("VANISHED 2")
        .assert_contains("* 3 EXISTS");
    imap.send("STATUS Pecorino (HIGHESTMODSEQ)").await;
    modseqs.push(
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .into_highest_modseq(),
    );

    // Fetch changes since SEQ 0
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[0]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FETCH (", 3)
        .assert_count("VANISHED", 0);

    // Fetch changes since SEQ 1, UID MOVE should count as a deletion
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[1]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 1)
        .assert_contains("VANISHED (EARLIER) 1")
        .assert_count("FETCH (", 3);

    // Fetch changes since SEQ 3
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[3]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 1)
        .assert_contains("VANISHED (EARLIER) 1:2") // .assert_contains("VANISHED (EARLIER) 2")
        .assert_count("FETCH (", 3);

    // Fetch changes since SEQ 4
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[4]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 1)
        .assert_contains("VANISHED (EARLIER) 1:2") // .assert_contains("VANISHED (EARLIER) 2")
        .assert_count("FETCH (", 2);

    // Fetch changes since SEQ 6
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[6]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 1)
        .assert_contains("VANISHED (EARLIER) 1:2") // .assert_contains("VANISHED (EARLIER) 2")
        .assert_count("FETCH (", 1);

    // Fetch changes since SEQ 7
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[7]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 1)
        .assert_contains("VANISHED (EARLIER) 1:2") // .assert_contains("VANISHED (EARLIER) 2")
        .assert_count("FETCH (", 0);

    // Fetch changes since SEQ 8
    imap.send(&format!(
        "UID FETCH 1:* (FLAGS) (CHANGEDSINCE {} VANISHED)",
        modseqs[8]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("VANISHED", 0)
        .assert_count("FETCH (", 0);

    // Search since MODSEQ
    imap.send(&format!("SEARCH RETURN (ALL) MODSEQ {}", modseqs[3]))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("ALL 1:3 MODSEQ");

    imap_check.send("NOOP").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("3 EXISTS");
    imap_check
        .send(&format!("SEARCH MODSEQ {}", modseqs[4]))
        .await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("SEARCH 2 3 (MODSEQ");

    // Store unchanged since
    imap.send(&format!(
        "UID STORE 2:5 (UNCHANGEDSINCE {}) +FLAGS.SILENT (\\Junk)",
        modseqs[5]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH")
        .assert_contains("UID 3)")
        .assert_count("FETCH (", 1)
        .assert_contains("[MODIFIED 2,4:5]");

    imap.send(&format!(
        "UID STORE 4,5 (UNCHANGEDSINCE {}) -FLAGS.SILENT (\\Answered)",
        modseqs[6]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 2 FETCH")
        .assert_contains("UID 4)")
        .assert_count("FETCH (", 1)
        .assert_contains("[MODIFIED 5]");

    // QResync
    imap.send("STATUS Pecorino (UIDVALIDITY)").await;
    let uid_validity = imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .into_uid_validity();

    imap.send(&format!(
        "SELECT Pecorino (QRESYNC ({} {} 1:5)) ",
        uid_validity, modseqs[6]
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("FETCH (", 3)
        .assert_contains("VANISHED (EARLIER) 1:2"); // .assert_contains("VANISHED (EARLIER) 2");
}
