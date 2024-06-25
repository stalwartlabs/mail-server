/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::ResponseType;

use crate::imap::{expand_uid_list, AssertResult};

use super::{append::build_messages, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection) {
    println!("Running THREAD tests...");

    // Create test messages
    let messages = build_messages();

    // Insert messages using Multiappend
    imap.send("CREATE Manchego").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    for (pos, message) in messages.iter().enumerate() {
        if pos == 0 {
            imap.send(&format!("APPEND Manchego {{{}}}", message.len()))
                .await;
        } else {
            imap.send_untagged(&format!(" {{{}}}", message.len())).await;
        }
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        if pos < messages.len() - 1 {
            imap.send_raw(message).await;
        } else {
            imap.send_untagged(message).await;
            assert_eq!(
                expand_uid_list(
                    &imap
                        .assert_read(Type::Tagged, ResponseType::Ok)
                        .await
                        .into_append_uid()
                )
                .len(),
                messages.len(),
            );
        }
    }

    // Obtain ThreadId and MessageId of the first message
    imap.send("SELECT Manchego").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    let mut email_id = None;
    let mut thread_id = None;
    imap.send("UID FETCH 1 (EMAILID THREADID)").await;
    for line in imap.assert_read(Type::Tagged, ResponseType::Ok).await {
        if let Some((_, value)) = line.split_once("EMAILID (") {
            email_id = value
                .split_once(')')
                .expect("Missing delimiter")
                .0
                .to_string()
                .into();
        }
        if let Some((_, value)) = line.split_once("THREADID (") {
            thread_id = value
                .split_once(')')
                .expect("Missing delimiter")
                .0
                .to_string()
                .into();
        }
    }
    let email_id = email_id.expect("Missing EMAILID");
    let thread_id = thread_id.expect("Missing THREADID");

    // 4 different threads are expected
    imap.send("THREAD REFERENCES UTF-8 1:*").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("(1 2 3 4)")
        .assert_contains("(5 6 7 8)")
        .assert_contains("(9 10 11 12)");

    imap.send("THREAD REFERENCES UTF-8 SUBJECT T1").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("(5 6 7 8)")
        .assert_count("(1 2 3 4)", 0)
        .assert_count("(9 10 11 12)", 0);

    // Filter by threadId and messageId
    imap.send(&format!(
        "UID THREAD REFERENCES UTF-8 THREADID {}",
        thread_id
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("(1 2 3 4)")
        .assert_count("(", 1);

    imap.send(&format!("UID THREAD REFERENCES UTF-8 EMAILID {}", email_id))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("(1)")
        .assert_count("(", 1);

    // Delete all messages
    imap.send("STORE 1:* +FLAGS.SILENT (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("EXPUNGE", 13);
}
