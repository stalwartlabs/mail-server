/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use ahash::AHashSet;
use jmap::{
    mailbox::{INBOX_ID, JUNK_ID, TRASH_ID},
    JMAP,
};
use jmap_proto::types::{collection::Collection, id::Id, property::Property};
use store::{
    write::{key::DeserializeBigEndian, TagValue},
    IterateParams, LogKey, U32_LEN, U64_LEN,
};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running purge tests...");
    let server = params.server.clone();
    let client = &mut params.client;
    let inbox_id = Id::from(INBOX_ID).to_string();
    let trash_id = Id::from(TRASH_ID).to_string();
    let junk_id = Id::from(JUNK_ID).to_string();

    // Create test messages
    client.set_default_account_id(Id::from(1u64));
    let mut message_ids = Vec::new();
    let mut pass = 0;
    let mut changes = AHashSet::new();

    loop {
        pass += 1;
        for folder_id in [&inbox_id, &trash_id, &junk_id] {
            message_ids.push(
                client
                    .email_import(
                        format!(
                            concat!(
                                "From: bill@example.com\r\n",
                                "To: jdoe@example.com\r\n",
                                "Subject: TPS Report #{} {}\r\n",
                                "\r\n",
                                "I'm going to need those TPS reports ASAP. ",
                                "So, if you could do that, that'd be great."
                            ),
                            pass, folder_id
                        )
                        .into_bytes(),
                        [folder_id],
                        None::<Vec<&str>>,
                        None,
                    )
                    .await
                    .unwrap()
                    .take_id(),
            );
        }

        if pass == 1 {
            changes = get_changes(&server).await;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        } else {
            break;
        }
    }

    // Make sure both messages and changes are present
    assert_eq!(
        server
            .get_document_ids(1, Collection::Email)
            .await
            .unwrap()
            .unwrap()
            .len(),
        6
    );

    // Purge junk/trash messages and old changes
    server.purge_account(1).await;

    // Only 4 messages should remain
    assert_eq!(
        server
            .get_document_ids(1, Collection::Email)
            .await
            .unwrap()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        server
            .get_tag(
                1,
                Collection::Email,
                Property::MailboxIds,
                TagValue::Id(INBOX_ID)
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        server
            .get_tag(
                1,
                Collection::Email,
                Property::MailboxIds,
                TagValue::Id(TRASH_ID)
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        server
            .get_tag(
                1,
                Collection::Email,
                Property::MailboxIds,
                TagValue::Id(JUNK_ID)
            )
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );

    // Compare changes
    let new_changes = get_changes(&server).await;
    assert!(!changes.is_empty());
    assert!(!new_changes.is_empty());
    for change in changes {
        assert!(
            !new_changes.contains(&change),
            "Change {:?} was not purged",
            change
        );
    }
}

async fn get_changes(server: &JMAP) -> AHashSet<(u64, u8)> {
    let mut changes = AHashSet::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(
                LogKey {
                    account_id: 0,
                    collection: 0,
                    change_id: 0,
                },
                LogKey {
                    account_id: u32::MAX,
                    collection: u8::MAX,
                    change_id: u64::MAX,
                },
            )
            .ascending()
            .no_values(),
            |key, _| {
                assert_eq!(key.deserialize_be_u32(0).unwrap(), 1);
                changes.insert((
                    key.deserialize_be_u64(key.len() - U64_LEN).unwrap(),
                    key[U32_LEN],
                ));
                Ok(true)
            },
        )
        .await
        .unwrap();
    changes
}
