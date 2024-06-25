/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use directory::backend::internal::manage::ManageDirectory;
use futures::StreamExt;
use jmap_client::{
    client_ws::WebSocketMessage,
    core::{
        response::{Response, TaggedMethodResponse},
        set::SetObject,
    },
    TypeState,
};
use jmap_proto::types::id::Id;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::jmap::{assert_is_empty, mailbox::destroy_all_mailboxes, test_account_login};

use super::JMAPTest;

pub async fn test(params: &mut JMAPTest) {
    println!("Running WebSockets tests...");
    let server = params.server.clone();

    // Authenticate all accounts
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

    let mut ws_stream = client.connect_ws().await.unwrap();

    let (stream_tx, mut stream_rx) = mpsc::channel::<WebSocketMessage>(100);

    tokio::spawn(async move {
        while let Some(change) = ws_stream.next().await {
            stream_tx.send(change.unwrap()).await.unwrap();
        }
    });

    // Create mailbox
    let mut request = client.build();
    let create_id = request
        .set_mailbox()
        .create()
        .name("WebSocket Test")
        .create_id()
        .unwrap();
    let request_id = request.send_ws().await.unwrap();
    let mut response = expect_response(&mut stream_rx).await;
    assert_eq!(request_id, response.request_id().unwrap());
    let mailbox_id = response
        .pop_method_response()
        .unwrap()
        .unwrap_set_mailbox()
        .unwrap()
        .created(&create_id)
        .unwrap()
        .take_id();

    // Enable push notifications
    client
        .enable_push_ws(None::<Vec<_>>, None::<&str>)
        .await
        .unwrap();

    // Make changes over standard HTTP and expect a push notification via WebSockets
    client
        .mailbox_update_sort_order(&mailbox_id, 1)
        .await
        .unwrap();
    assert_state(&mut stream_rx, &account_id, &[TypeState::Mailbox]).await;

    // Multiple changes should be grouped and delivered in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_state(&mut stream_rx, &account_id, &[TypeState::Mailbox]).await;
    expect_nothing(&mut stream_rx).await;

    // Disable push notifications
    client.disable_push_ws().await.unwrap();

    // No more changes should be received
    let mut request = client.build();
    request.set_mailbox().destroy([&mailbox_id]);
    request.send_ws().await.unwrap();
    expect_response(&mut stream_rx)
        .await
        .pop_method_response()
        .unwrap()
        .unwrap_set_mailbox()
        .unwrap()
        .destroyed(&mailbox_id)
        .unwrap();
    expect_nothing(&mut stream_rx).await;

    params.client.set_default_account_id(account_id);
    destroy_all_mailboxes(params).await;
    assert_is_empty(server).await;
}

async fn expect_response(
    stream_rx: &mut mpsc::Receiver<WebSocketMessage>,
) -> Response<TaggedMethodResponse> {
    match tokio::time::timeout(Duration::from_millis(100), stream_rx.recv()).await {
        Ok(Some(message)) => match message {
            WebSocketMessage::Response(response) => response,
            _ => panic!("Expected response, got: {:?}", message),
        },
        result => {
            panic!("Timeout waiting for websocket: {:?}", result);
        }
    }
}

async fn assert_state(
    stream_rx: &mut mpsc::Receiver<WebSocketMessage>,
    id: &str,
    state: &[TypeState],
) {
    match tokio::time::timeout(Duration::from_millis(700), stream_rx.recv()).await {
        Ok(Some(message)) => match message {
            WebSocketMessage::StateChange(changes) => {
                assert_eq!(
                    changes
                        .changes(id)
                        .unwrap()
                        .map(|x| x.0)
                        .collect::<AHashSet<&TypeState>>(),
                    state.iter().collect::<AHashSet<&TypeState>>()
                );
            }
            _ => panic!("Expected state change, got: {:?}", message),
        },
        result => {
            panic!("Timeout waiting for websocket: {:?}", result);
        }
    }
}

async fn expect_nothing(stream_rx: &mut mpsc::Receiver<WebSocketMessage>) {
    match tokio::time::timeout(Duration::from_millis(1000), stream_rx.recv()).await {
        Err(_) => {}
        message => {
            panic!("Received a message when expecting nothing: {:?}", message);
        }
    }
}
