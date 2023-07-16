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

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jmap_proto::error::request::RequestError;
use tokio_tungstenite::WebSocketStream;
use tungstenite::{handshake::derive_accept_key, protocol::Role};
use utils::listener::ServerInstance;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse},
    auth::AccessToken,
    JMAP,
};

pub async fn upgrade_websocket_connection(
    jmap: Arc<JMAP>,
    req: HttpRequest,
    access_token: Arc<AccessToken>,
    instance: Arc<ServerInstance>,
) -> HttpResponse {
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
        return RequestError::blank(
            StatusCode::BAD_REQUEST.as_u16(),
            "WebSocket upgrade failed",
            "Missing or Invalid Connection or Upgrade headers.",
        )
        .into_http_response();
    }
    let derived_key = match (
        headers
            .get("Sec-WebSocket-Key")
            .and_then(|h| h.to_str().ok()),
        headers
            .get("Sec-WebSocket-Version")
            .and_then(|h| h.to_str().ok()),
    ) {
        (Some(key), Some(version)) if version == "13" => derive_accept_key(key.as_bytes()),
        _ => {
            return RequestError::blank(
                StatusCode::BAD_REQUEST.as_u16(),
                "WebSocket upgrade failed",
                "Missing or Invalid Sec-WebSocket-Key headers.",
            )
            .into_http_response();
        }
    };

    // Spawn WebSocket connection
    tokio::spawn(async move {
        // Upgrade connection
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                jmap.handle_websocket_stream(
                    WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None)
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

    Response::builder()
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
        .unwrap()
}
