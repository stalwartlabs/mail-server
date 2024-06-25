/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use common::listener::ServerInstance;
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use jmap_proto::{
    error::request::RequestError,
    request::websocket::{
        WebSocketMessage, WebSocketRequestError, WebSocketResponse, WebSocketStateChange,
    },
    types::type_state::DataType,
};
use tokio_tungstenite::WebSocketStream;
use tungstenite::Message;
use utils::map::bitmap::Bitmap;

use crate::{auth::AccessToken, JMAP};

impl JMAP {
    pub async fn handle_websocket_stream(
        &self,
        mut stream: WebSocketStream<TokioIo<Upgraded>>,
        access_token: Arc<AccessToken>,
        instance: Arc<ServerInstance>,
    ) {
        let span = tracing::info_span!(
            "WebSocket connection established",
            "account_id" = access_token.primary_id(),
        );

        // Set timeouts
        let throttle = self.core.jmap.web_socket_throttle;
        let timeout = self.core.jmap.web_socket_timeout;
        let heartbeat = self.core.jmap.web_socket_heartbeat;
        let mut last_request = Instant::now();
        let mut last_changes_sent = Instant::now() - throttle;
        let mut last_heartbeat = Instant::now() - heartbeat;
        let mut next_event = heartbeat;

        // Register with state manager
        let mut change_rx = if let Some(change_rx) = self
            .subscribe_state_manager(access_token.primary_id(), Bitmap::all())
            .await
        {
            change_rx
        } else {
            let _ = stream
                .send(Message::Text(
                    WebSocketRequestError::from(RequestError::internal_server_error()).to_json(),
                ))
                .await;
            return;
        };
        let mut changes = WebSocketStateChange::new(None);
        let mut change_types: Bitmap<DataType> = Bitmap::new();

        loop {
            tokio::select! {
                event = tokio::time::timeout(next_event, stream.next()) => {
                    match event {
                        Ok(Some(Ok(event))) => {
                            match event {
                                Message::Text(text) => {
                                    let response = match WebSocketMessage::parse(
                                        text.as_bytes(),
                                        self.core.jmap.request_max_calls,
                                        self.core.jmap.request_max_size,
                                    ) {
                                        Ok(WebSocketMessage::Request(request)) => {
                                            match self
                                                .handle_request(
                                                    request.request,
                                                    access_token.clone(),
                                                    &instance,
                                                )
                                                .await
                                            {
                                                Ok(response) => {
                                                    WebSocketResponse::from_response(response, request.id)
                                                        .to_json()
                                                }
                                                Err(err) => {
                                                    WebSocketRequestError::from_error(err, request.id)
                                                        .to_json()
                                                }
                                            }
                                        }
                                        Ok(WebSocketMessage::PushEnable(push_enable)) => {
                                            change_types = if !push_enable.data_types.is_empty() {
                                                push_enable.data_types.into()
                                            } else {
                                                Bitmap::all()
                                            };
                                            continue;
                                        }
                                        Ok(WebSocketMessage::PushDisable) => {
                                            change_types = Bitmap::new();
                                            continue;
                                        }
                                        Err(err) => err.to_json(),
                                    };
                                    if let Err(err) = stream.send(Message::Text(response)).await {
                                        tracing::debug!(parent: &span, error = ?err, "Failed to send text message");
                                    }
                                }
                                Message::Ping(bytes) => {
                                    if let Err(err) = stream.send(Message::Pong(bytes)).await {
                                        tracing::debug!(parent: &span, error = ?err, "Failed to send pong message");
                                    }
                                }
                                Message::Close(frame) => {
                                    let _ = stream.close(frame).await;
                                    break;
                                }
                                _ => (),
                            }

                            last_request = Instant::now();
                            last_heartbeat = Instant::now();
                        }
                        Ok(Some(Err(err))) => {
                            tracing::debug!(parent: &span, error = ?err, "Websocket error");
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            // Verify timeout
                            if last_request.elapsed() > timeout {
                                tracing::debug!(
                                    parent: &span,
                                    event = "disconnect",
                                    "Disconnecting idle client"
                                );
                                break;
                            }
                        }
                    }
                }
                state_change = change_rx.recv() => {
                    if let Some(state_change) = state_change {
                        if !change_types.is_empty() && state_change
                            .types
                            .iter()
                            .any(|(t, _)| change_types.contains(*t))
                            {
                                for (type_state, change_id) in state_change.types {
                                    changes
                                        .changed
                                        .get_mut_or_insert(state_change.account_id.into())
                                        .set(type_state, change_id.into());
                                }
                            }
                    } else {
                        tracing::debug!(
                            parent: &span,
                            event = "channel-closed",
                            "Disconnecting client, channel closed"
                        );
                        break;
                    }
                }
            }

            if !changes.changed.is_empty() {
                // Send any queued changes
                let elapsed = last_changes_sent.elapsed();
                if elapsed >= throttle {
                    if let Err(err) = stream.send(Message::Text(changes.to_json())).await {
                        tracing::debug!(parent: &span, error = ?err, "Failed to send state change message");
                    }
                    changes.changed.clear();
                    last_changes_sent = Instant::now();
                    last_heartbeat = Instant::now();
                    next_event = heartbeat;
                } else {
                    next_event = throttle - elapsed;
                }
            } else if last_heartbeat.elapsed() > heartbeat {
                if let Err(err) = stream.send(Message::Ping(vec![])).await {
                    tracing::debug!(parent: &span, error = ?err, "Failed to send ping message");
                    break;
                }
                last_heartbeat = Instant::now();
                next_event = heartbeat;
            }
        }
    }
}
