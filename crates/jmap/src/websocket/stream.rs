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
use trc::JmapEvent;
use tungstenite::Message;
use utils::map::bitmap::Bitmap;

use crate::{
    api::http::{HttpSessionData, ToRequestError},
    auth::AccessToken,
    JMAP,
};

impl JMAP {
    pub async fn handle_websocket_stream(
        &self,
        mut stream: WebSocketStream<TokioIo<Upgraded>>,
        access_token: Arc<AccessToken>,
        session: HttpSessionData,
    ) {
        trc::event!(
            Jmap(JmapEvent::WebsocketStart),
            SessionId = session.session_id,
            AccountId = access_token.primary_id(),
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
        let mut change_rx = match self
            .subscribe_state_manager(access_token.primary_id(), Bitmap::all())
            .await
        {
            Ok(change_rx) => change_rx,
            Err(err) => {
                trc::error!(err
                    .details("Failed to subscribe to state manager")
                    .session_id(session.session_id));

                let _ = stream
                    .send(Message::Text(
                        WebSocketRequestError::from(RequestError::internal_server_error())
                            .to_json(),
                    ))
                    .await;
                return;
            }
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
                                            let response = self
                                                .handle_request(
                                                    request.request,
                                                    access_token.clone(),
                                                    &session,
                                                )
                                                .await;

                                            WebSocketResponse::from_response(response, request.id)
                                            .to_json()
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
                                        Err(err) => {
                                            let response = WebSocketRequestError::from(err.to_request_error()).to_json();
                                            trc::error!(err.details("Failed to parse WebSocket message").session_id(session.session_id));
                                            response
                                        },
                                    };
                                    if let Err(err) = stream.send(Message::Text(response)).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send text message",
                                                    SessionId = session.session_id,
                                                    Reason = err.to_string()
                                        );
                                    }
                                }
                                Message::Ping(bytes) => {
                                    if let Err(err) = stream.send(Message::Pong(bytes)).await {
                                        trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Failed to send pong message",
                                                    SessionId = session.session_id,
                                                    Reason = err.to_string()
                                        );
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
                            trc::event!(Jmap(JmapEvent::WebsocketError),
                                                    Details = "Websocket error",
                                                    SessionId = session.session_id,
                                                    Reason = err.to_string()
                                        );
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            // Verify timeout
                            if last_request.elapsed() > timeout {
                                trc::event!(
                                    Jmap(JmapEvent::WebsocketStop),
                                    SessionId = session.session_id,
                                    Reason = "Idle client"
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
                        trc::event!(
                            Jmap(JmapEvent::WebsocketStop),
                            SessionId = session.session_id,
                            Reason = "State manager channel closed"
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
                        trc::event!(
                            Jmap(JmapEvent::WebsocketError),
                            Details = "Failed to send state change message.",
                            SessionId = session.session_id,
                            Reason = err.to_string()
                        );
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
                    trc::event!(
                        Jmap(JmapEvent::WebsocketError),
                        Details = "Failed to send ping message.",
                        SessionId = session.session_id,
                        Reason = err.to_string()
                    );
                    break;
                }
                last_heartbeat = Instant::now();
                next_event = heartbeat;
            }
        }
    }
}
