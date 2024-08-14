/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::time::{Duration, Instant};

use common::telemetry::tracers::store::{TracingQuery, TracingStore};
use directory::backend::internal::manage;
use http_body_util::{combinators::BoxBody, StreamBody};
use hyper::{
    body::{Bytes, Frame},
    Method, StatusCode,
};
use mail_parser::DateTime;
use serde_json::json;
use store::ahash::{AHashMap, AHashSet};
use trc::{
    ipc::{bitset::Bitset, subscriber::SubscriberBuilder},
    Key, Value,
};
use utils::{snowflake::SnowflakeIdGenerator, url_params::UrlParams};

use crate::{
    api::{
        http::ToHttpResponse, management::Timestamp, HttpRequest, HttpResponse, HttpResponseBody,
        JsonResponse,
    },
    JMAP,
};

impl JMAP {
    pub async fn handle_tracing_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());

        match (
            path.get(2).copied().unwrap(),
            path.get(3).copied(),
            req.method(),
        ) {
            ("spans", None, &Method::GET) => {
                let page: usize = params.parse("page").unwrap_or(0);
                let limit: usize = params.parse("limit").unwrap_or(0);
                let mut tracing_query = Vec::new();
                if let Some(typ) = params.parse("type") {
                    tracing_query.push(TracingQuery::EventType(typ));
                }
                if let Some(queue_id) = params.parse("queue_id") {
                    tracing_query.push(TracingQuery::QueueId(queue_id));
                }
                if let Some(query) = params.get("filter") {
                    let mut buf = String::with_capacity(query.len());
                    let mut in_quote = false;
                    for ch in query.chars() {
                        if ch.is_ascii_whitespace() {
                            if in_quote {
                                buf.push(' ');
                            } else if !buf.is_empty() {
                                tracing_query.push(TracingQuery::Keywords(buf));
                                buf = String::new();
                            }
                        } else if ch == '"' {
                            buf.push(ch);
                            if in_quote {
                                if !buf.is_empty() {
                                    tracing_query.push(TracingQuery::Keywords(buf));
                                    buf = String::new();
                                }
                                in_quote = false;
                            } else {
                                in_quote = true;
                            }
                        } else {
                            buf.push(ch);
                        }
                    }
                    if !buf.is_empty() {
                        tracing_query.push(TracingQuery::Keywords(buf));
                    }
                }
                let before = params
                    .parse::<Timestamp>("before")
                    .map(|t| t.into_inner())
                    .and_then(SnowflakeIdGenerator::from_timestamp)
                    .unwrap_or(0);
                let after = params
                    .parse::<Timestamp>("after")
                    .map(|t| t.into_inner())
                    .and_then(SnowflakeIdGenerator::from_timestamp)
                    .unwrap_or(0);
                let span_ids = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_store.as_ref())
                    .ok_or_else(|| {
                        manage::error("Unavailable", "No tracing store has been configured".into())
                    })?
                    .query_spans(&tracing_query, after, before)
                    .await?;

                let (total, span_ids) = if limit > 0 {
                    let offset = page.saturating_sub(1) * limit;
                    (
                        span_ids.len(),
                        span_ids.into_iter().skip(offset).take(limit).collect(),
                    )
                } else {
                    (span_ids.len(), span_ids)
                };

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": span_ids,
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            ("span", id, &Method::GET) => {
                let store = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_store.as_ref())
                    .ok_or_else(|| {
                        manage::error("Unavailable", "No tracing store has been configured".into())
                    })?;

                let mut events = Vec::new();
                for span_id in id
                    .or_else(|| params.get("id"))
                    .unwrap_or_default()
                    .split(',')
                {
                    if let Ok(span_id) = span_id.parse::<u64>() {
                        events.push(store.get_span(span_id).await?);
                    }
                }

                Ok(JsonResponse::new(json!({
                        "data": events,
                }))
                .into_http_response())
            }
            ("live", None, &Method::GET) => {
                let mut filters = AHashMap::new();

                for (key, value) in params.into_inner() {
                    if let Some(key) = Key::try_parse(key.as_ref()) {
                        filters.insert(key, value.into_owned());
                    }
                }

                let (_, mut rx) = SubscriberBuilder::new("live-tracer".to_string())
                    .with_interests(Box::new(Bitset::all()))
                    .with_lossy(false)
                    .register();
                let throttle = Duration::from_secs(1);
                let ping_interval = Duration::from_secs(30);
                let ping_payload = Bytes::from(format!(
                    "event: ping\ndata: {{\"interval\": {}}}\n\n",
                    ping_interval.as_millis()
                ));
                let mut last_ping = Instant::now();
                let mut events = Vec::new();
                let mut active_span_ids = AHashSet::new();

                Ok(HttpResponse {
                    status: StatusCode::OK,
                    content_type: "text/event-stream".into(),
                    content_disposition: "".into(),
                    cache_control: "no-store".into(),
                    body: HttpResponseBody::Stream(BoxBody::new(StreamBody::new(
                        async_stream::stream! {
                            let mut last_message = Instant::now() - throttle;
                            let mut timeout = ping_interval;

                            loop {
                                match tokio::time::timeout(timeout, rx.recv()).await {
                                    Ok(Some(event_batch)) => {
                                        for event in event_batch {
                                            if filters.is_empty()
                                                || event
                                                    .span_id()
                                                    .map_or(false, |span_id| active_span_ids.contains(&span_id))
                                            {
                                                events.push(event);
                                            } else {
                                                let mut matched_keys = AHashSet::new();
                                                for (key, value) in event
                                                    .keys
                                                    .iter()
                                                    .chain(event.inner.span.as_ref().map_or(([]).iter(), |s| s.keys.iter()))
                                                {
                                                    if let Some(needle) = filters.get(key) {
                                                        let matches = match value {
                                                            Value::Static(haystack) => haystack.contains(needle),
                                                            Value::String(haystack) => haystack.contains(needle),
                                                            Value::UInt(haystack) => haystack.to_string().contains(needle),
                                                            Value::Int(haystack) => haystack.to_string().contains(needle),
                                                            Value::Float(haystack) => haystack.to_string().contains(needle),
                                                            Value::Timestamp(haystack) => {
                                                                DateTime::from_timestamp(*haystack as i64)
                                                                    .to_rfc3339()
                                                                    .contains(needle)
                                                            }
                                                            Value::Duration(haystack) => {
                                                                haystack.to_string().contains(needle)
                                                            }
                                                            Value::Bytes(haystack) => std::str::from_utf8(haystack)
                                                                .unwrap_or_default()
                                                                .contains(needle),
                                                            Value::Bool(true) => needle == "true",
                                                            Value::Bool(false) => needle == "false",
                                                            Value::Ipv4(haystack) => haystack.to_string().contains(needle),
                                                            Value::Ipv6(haystack) => haystack.to_string().contains(needle),
                                                            Value::Event(_) | Value::Array(_) | Value::None => false,
                                                        };

                                                        if matches {
                                                            matched_keys.insert(*key);
                                                            if matched_keys.len() == filters.len() {
                                                                if let Some(span_id) = event.span_id() {
                                                                    active_span_ids.insert(span_id);
                                                                }
                                                                events.push(event);
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        break;
                                    }
                                    Err(_) => (),
                                }

                                timeout = if !events.is_empty() {
                                    let elapsed = last_message.elapsed();
                                    if elapsed >= throttle {
                                        last_message = Instant::now();
                                        yield Ok(Frame::data(Bytes::from(format!(
                                            "event: state\ndata: {}\n\n",
                                            serde_json::to_string(&events).unwrap()
                                        ))));

                                        events.clear();
                                        ping_interval
                                    } else {
                                        throttle - elapsed
                                    }
                                } else {
                                    let elapsed = last_ping.elapsed();
                                    if elapsed >= ping_interval {
                                        last_ping = Instant::now();
                                        yield Ok(Frame::data(ping_payload.clone()));
                                        ping_interval
                                    } else {
                                        ping_interval - elapsed
                                    }
                                };
                            }
                        },
                    ))),
                })
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
