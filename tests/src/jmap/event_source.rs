/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::jmap::{
    assert_is_empty, delivery::SmtpConnection, mailbox::destroy_all_mailboxes, test_account_login,
};
use directory::backend::internal::manage::ManageDirectory;
use futures::StreamExt;
use jmap::mailbox::INBOX_ID;
use jmap_client::{event_source::Changes, mailbox::Role, TypeState};
use jmap_proto::types::id::Id;
use store::ahash::AHashSet;

use tokio::sync::mpsc;

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running EventSource tests...");

    // Create test account
    let server = params.server.clone();
    params
        .directory
        .create_test_user_with_email("jdoe@example.com", "12345", "John Doe")
        .await;
    let account_id = Id::from(
        server
            .core
            .storage
            .data
            .get_or_create_account_id("jdoe@example.com")
            .await
            .unwrap(),
    )
    .to_string();
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
    params.client.set_default_account_id(account_id.to_string());
    params
        .client
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

    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
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
