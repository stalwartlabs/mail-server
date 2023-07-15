/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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

use imap_proto::ResponseType;

use super::{AssertResult, ImapConnection, Type};

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection) {
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
