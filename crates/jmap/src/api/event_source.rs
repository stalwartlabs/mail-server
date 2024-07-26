/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use http_body_util::{combinators::BoxBody, StreamBody};
use hyper::{
    body::{Bytes, Frame},
    StatusCode,
};
use jmap_proto::types::type_state::DataType;
use utils::map::bitmap::Bitmap;

use crate::{auth::AccessToken, JMAP, LONG_SLUMBER};

use super::{HttpRequest, HttpResponse, HttpResponseBody, StateChangeResponse};

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
    ) -> trc::Result<HttpResponse> {
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
                            return Err(trc::ResourceEvent::BadParameters.into_err());
                        }
                    }
                }
                "closeafter" => match value.as_ref() {
                    "state" => {
                        close_after_state = true;
                    }
                    "no" => {}
                    _ => return Err(trc::ResourceEvent::BadParameters.into_err()),
                },
                "ping" => match value.parse::<u32>() {
                    Ok(value) => {
                        ping = value;
                    }
                    Err(_) => return Err(trc::ResourceEvent::BadParameters.into_err()),
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
        let mut change_rx = self
            .subscribe_state_manager(access_token.primary_id(), types)
            .await?;

        Ok(HttpResponse {
            status: StatusCode::OK,
            content_type: "text/event-stream".into(),
            content_disposition: "".into(),
            cache_control: "no-store".into(),
            body: HttpResponseBody::Stream(BoxBody::new(StreamBody::new(async_stream::stream! {
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
            }))),
        })
    }
}
