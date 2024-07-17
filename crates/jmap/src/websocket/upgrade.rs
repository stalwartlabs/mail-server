/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use common::listener::ServerInstance;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Response};
use hyper_util::rt::TokioIo;
use tokio_tungstenite::WebSocketStream;
use tungstenite::{handshake::derive_accept_key, protocol::Role};

use crate::{
    api::{HttpRequest, HttpResponse},
    auth::AccessToken,
    JMAP,
};

impl JMAP {
    pub async fn upgrade_websocket_connection(
        &self,
        req: HttpRequest,
        access_token: Arc<AccessToken>,
        instance: Arc<ServerInstance>,
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
            return Err(trc::ResourceCause::BadParameters
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
                return Err(trc::ResourceCause::BadParameters
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
                        instance,
                    )
                    .await;
                }
                Err(e) => {
                    tracing::debug!("WebSocket upgrade failed: {}", e);
                }
            }
        });

        Ok(Response::builder()
            .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
            .header(hyper::header::CONNECTION, "upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .header("Sec-WebSocket-Accept", &derived_key)
            .header("Sec-WebSocket-Protocol", "jmap")
            .body(
                Full::new(Bytes::from("Switching to WebSocket protocol"))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap())
    }
}
