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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use http_body_util::{combinators::BoxBody, StreamBody};
use hyper::{
    body::{Bytes, Frame},
    header, StatusCode,
};
use jmap_proto::{error::request::RequestError, types::type_state::DataType};
use utils::map::bitmap::Bitmap;

use crate::{auth::AccessToken, JMAP, LONG_SLUMBER};

use super::{http::ToHttpResponse, HttpRequest, HttpResponse, StateChangeResponse};

struct Ping {
    interval: Duration,
    last_ping: Instant,
    payload: Bytes,
}

impl JMAP {
    pub async fn handle_event_source(
        &self,
        req: HttpRequest,
        access_token: Arc<AccessToken>,
    ) -> HttpResponse {
        // Parse query
        let mut ping = 0;
        let mut types = Bitmap::default();
        let mut close_after_state = false;

        for (key, value) in form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes())
        {
            match key.as_ref() {
                "types" => {
                    for type_state in value.split(',') {
                        if type_state == "*" {
                            types = Bitmap::all();
                            break;
                        } else if let Ok(type_state) = DataType::try_from(type_state) {
                            types.insert(type_state);
                        } else {
                            return RequestError::invalid_parameters().into_http_response();
                        }
                    }
                }
                "closeafter" => match value.as_ref() {
                    "state" => {
                        close_after_state = true;
                    }
                    "no" => {}
                    _ => return RequestError::invalid_parameters().into_http_response(),
                },
                "ping" => match value.parse::<u32>() {
                    Ok(value) => {
                        ping = value;
                    }
                    Err(_) => return RequestError::invalid_parameters().into_http_response(),
                },
                _ => {}
            }
        }

        let mut ping = if ping > 0 {
            #[cfg(not(feature = "test_mode"))]
            let interval = std::cmp::max(ping, 30) * 1000;
            #[cfg(feature = "test_mode")]
            let interval = ping * 1000;

            Ping {
                interval: Duration::from_millis(interval as u64),
                last_ping: Instant::now() - Duration::from_millis(interval as u64),
                payload: Bytes::from(format!(
                    "event: ping\ndata: {{\"interval\": {}}}\n\n",
                    interval
                )),
            }
            .into()
        } else {
            None
        };
        let mut response = StateChangeResponse::new();
        let throttle = self.core.jmap.event_source_throttle;

        // Register with state manager
        let mut change_rx = if let Some(change_rx) = self
            .subscribe_state_manager(access_token.primary_id(), types)
            .await
        {
            change_rx
        } else {
            return RequestError::internal_server_error().into_http_response();
        };

        hyper::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-store")
            .body(BoxBody::new(StreamBody::new(async_stream::stream! {
                let mut last_message = Instant::now() - throttle;
                let mut timeout =
                    ping.as_ref().map(|p| p.interval).unwrap_or(LONG_SLUMBER);

                loop {
                    match tokio::time::timeout(timeout, change_rx.recv()).await {
                        Ok(Some(state_change)) => {
                            for (type_state, change_id) in state_change.types {
                                response
                                    .changed
                                    .get_mut_or_insert(state_change.account_id.into())
                                    .set(type_state, change_id.into());
                            }
                        }
                        Ok(None) => {
                            tracing::debug!("Broadcast channel was closed.");
                            break;
                        }
                        Err(_) => (),
                    }

                    timeout = if !response.changed.is_empty() {
                        let elapsed = last_message.elapsed();
                        if elapsed >= throttle {
                            last_message = Instant::now();
                            yield Ok(Frame::data(Bytes::from(format!(
                                "event: state\ndata: {}\n\n",
                                serde_json::to_string(&response).unwrap()
                            ))));

                            if close_after_state {
                                break;
                            }

                            response.changed.clear();
                                ping.as_ref().map(|p| p.interval).unwrap_or(LONG_SLUMBER)
                        } else {
                            throttle - elapsed
                        }
                    } else if let Some(ping) = &mut ping {
                        let elapsed = ping.last_ping.elapsed();
                        if elapsed >= ping.interval {
                            ping.last_ping = Instant::now();
                            yield Ok(Frame::data(ping.payload.clone()));
                            ping.interval
                        } else {
                            ping.interval - elapsed
                        }
                    } else {
                        LONG_SLUMBER
                    };
                }
            })))
            .unwrap()
    }
}
