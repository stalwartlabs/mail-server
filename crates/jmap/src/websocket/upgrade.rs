/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use trc::JmapEvent;
use tungstenite::{handshake::derive_accept_key, protocol::Role};

use crate::{
    api::{http::HttpSessionData, HttpRequest, HttpResponse, HttpResponseBody},
    auth::AccessToken,
    JMAP,
};

impl JMAP {
    pub async fn upgrade_websocket_connection(
        &self,
        req: HttpRequest,
        access_token: Arc<AccessToken>,
        session: HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let headers = req.headers();
        if headers
            .get(hyper::header::CONNECTION)
            .and_then(|h| h.to_str().ok())
            != Some("Upgrade")
            || headers
                .get(hyper::header::UPGRADE)
                .and_then(|h| h.to_str().ok())
                != Some("websocket")
        {
            return Err(trc::ResourceEvent::BadParameters
                .into_err()
                .details("WebSocket upgrade failed")
                .ctx(
                    trc::Key::Reason,
                    "Missing or Invalid Connection or Upgrade headers.",
                ));
        }
        let derived_key = match (
            headers
                .get("Sec-WebSocket-Key")
                .and_then(|h| h.to_str().ok()),
            headers
                .get("Sec-WebSocket-Version")
                .and_then(|h| h.to_str().ok()),
        ) {
            (Some(key), Some("13")) => derive_accept_key(key.as_bytes()),
            _ => {
                return Err(trc::ResourceEvent::BadParameters
                    .into_err()
                    .details("WebSocket upgrade failed")
                    .ctx(
                        trc::Key::Reason,
                        "Missing or Invalid Sec-WebSocket-Key headers.",
                    ));
            }
        };

        // Spawn WebSocket connection
        let jmap = self.clone();
        tokio::spawn(async move {
            // Upgrade connection
            let session_id = session.session_id;
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    jmap.handle_websocket_stream(
                        WebSocketStream::from_raw_socket(
                            TokioIo::new(upgraded),
                            Role::Server,
                            None,
                        )
                        .await,
                        access_token,
                        session,
                    )
                    .await;
                }
                Err(err) => {
                    trc::event!(
                        Jmap(JmapEvent::WebsocketError),
                        Details = "Websocket upgrade failed",
                        SpanId = session_id,
                        Reason = err.to_string()
                    );
                }
            }
        });

        Ok(HttpResponse {
            status: StatusCode::SWITCHING_PROTOCOLS,
            content_type: "".into(),
            content_disposition: "".into(),
            cache_control: "".into(),
            body: HttpResponseBody::WebsocketUpgrade(derived_key),
        })
    }
}
