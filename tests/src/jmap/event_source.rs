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

use std::{sync::Arc, time::Duration};

use crate::{
    directory::sql::create_test_user_with_email,
    jmap::{delivery::SmtpConnection, mailbox::destroy_all_mailboxes, test_account_login},
};
use futures::StreamExt;
use jmap::{mailbox::INBOX_ID, JMAP};
use jmap_client::{client::Client, event_source::Changes, mailbox::Role, TypeState};
use jmap_proto::types::id::Id;
use store::ahash::AHashSet;

use tokio::sync::mpsc;

pub async fn test(server: Arc<JMAP>, admin_client: &mut Client) {
    println!("Running EventSource tests...");

    // Create test account
    let directory = server.directory.as_ref();
    create_test_user_with_email(directory, "jdoe@example.com", "12345", "John Doe").await;
    let account_id = Id::from(server.get_account_id("jdoe@example.com").await.unwrap()).to_string();
    let client = test_account_login("jdoe@example.com", "12345").await;

    let mut changes = client
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<Changes>(100);

    tokio::spawn(async move {
        while let Some(change) = changes.next().await {
            if let Err(_err) = event_tx.send(change.unwrap()).await {
                //println!("Error sending event: {}", _err);
                break;
            }
        }
    });

    assert_ping(&mut event_rx).await;

    // Create mailbox and expect state change
    let mailbox_id = client
        .mailbox_create("EventSource Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    assert_state(&mut event_rx, &account_id, &[TypeState::Mailbox]).await;

    // Multiple changes should be grouped and delivered in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    assert_state(&mut event_rx, &account_id, &[TypeState::Mailbox]).await;
    assert_ping(&mut event_rx).await; // Pings are only received in cfg(test)

    // Ingest email and expect state change
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    lmtp.quit().await;

    assert_state(
        &mut event_rx,
        &account_id,
        &[
            TypeState::EmailDelivery,
            TypeState::Email,
            TypeState::Thread,
            TypeState::Mailbox,
        ],
    )
    .await;
    assert_ping(&mut event_rx).await;

    // Destroy mailbox
    client.mailbox_destroy(&mailbox_id, true).await.unwrap();
    assert_state(&mut event_rx, &account_id, &[TypeState::Mailbox]).await;

    // Destroy Inbox
    admin_client.set_default_account_id(&account_id.to_string());
    admin_client
        .mailbox_destroy(&Id::from(INBOX_ID).to_string(), true)
        .await
        .unwrap();
    assert_state(
        &mut event_rx,
        &account_id,
        &[TypeState::Email, TypeState::Thread, TypeState::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;
    assert_ping(&mut event_rx).await;

    destroy_all_mailboxes(admin_client).await;
    server
        .store
        .assert_is_empty(server.blob_store.clone())
        .await;
}

async fn assert_state(
    event_rx: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    state: &[TypeState],
) {
    match tokio::time::timeout(Duration::from_millis(700), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert_eq!(
                changes
                    .changes(account_id)
                    .unwrap()
                    .map(|x| x.0)
                    .collect::<AHashSet<&TypeState>>(),
                state.iter().collect::<AHashSet<&TypeState>>()
            );
        }
        result => {
            panic!("Timeout waiting for event {:?}: {:?}", state, result);
        }
    }
}

async fn assert_ping(event_rx: &mut mpsc::Receiver<Changes>) {
    match tokio::time::timeout(Duration::from_millis(1100), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert!(changes.changes("ping").is_some(),);
        }
        _ => {
            panic!("Did not receive ping.");
        }
    }
}
