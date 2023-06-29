/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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
    // Test CAPABILITY
    imap.send("CAPABILITY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Test NOOP
    imap.send("NOOP").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Test ID
    imap.send("ID").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* ID (\"name\" \"Stalwart IMAP\" \"version\" ");

    // Login should be disabled
    imap.send("LOGIN jdoe@example.com secret").await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    // Try logging in with wrong password
    imap.send("AUTHENTICATE PLAIN {24}").await;
    imap.assert_read(Type::Continuation, ResponseType::Ok).await;
    imap.send_untagged("AGJvYXR5AG1jYm9hdGZhY2U=").await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;
}
