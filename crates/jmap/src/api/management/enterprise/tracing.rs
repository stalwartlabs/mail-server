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
    serializers::json::JsonEventSerializer,
    DeliveryEvent, EventType, Key, QueueEvent, Value,
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
        account_id: u32,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());

        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2).copied(),
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
                let values = params.get("values").is_some();
                let store = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_store.as_ref())
                    .ok_or_else(|| manage::unsupported("No tracing store has been configured"))?;
                let span_ids = store.query_spans(&tracing_query, after, before).await?;

                let (total, span_ids) = if limit > 0 {
                    let offset = page.saturating_sub(1) * limit;
                    (
                        span_ids.len(),
                        span_ids.into_iter().skip(offset).take(limit).collect(),
                    )
                } else {
                    (span_ids.len(), span_ids)
                };

                if values && !span_ids.is_empty() {
                    let mut values = Vec::with_capacity(span_ids.len());

                    for span_id in span_ids {
                        for event in store.get_span(span_id).await? {
                            if matches!(
                                event.inner.typ,
                                EventType::Delivery(DeliveryEvent::AttemptStart)
                                    | EventType::Queue(
                                        QueueEvent::QueueMessage
                                            | QueueEvent::QueueMessageAuthenticated
                                    )
                            ) {
                                values.push(event);
                                break;
                            }
                        }
                    }

                    Ok(JsonResponse::new(json!({
                            "data": {
                                "items": JsonEventSerializer::new(values).with_spans(),
                                "total": total,
                            },
                    }))
                    .into_http_response())
                } else {
                    Ok(JsonResponse::new(json!({
                            "data": {
                                "items": span_ids,
                                "total": total,
                            },
                    }))
                    .into_http_response())
                }
            }
            ("span", id, &Method::GET) => {
                let store = self
                    .core
                    .enterprise
                    .as_ref()
                    .and_then(|e| e.trace_store.as_ref())
                    .ok_or_else(|| manage::unsupported("No tracing store has been configured"))?;

                let mut events = Vec::new();
                for span_id in id
                    .or_else(|| params.get("id"))
                    .unwrap_or_default()
                    .split(',')
                {
                    if let Ok(span_id) = span_id.parse::<u64>() {
                        events.push(
                            JsonEventSerializer::new(store.get_span(span_id).await?)
                                .with_description()
                                .with_explanation(),
                        );
                    } else {
                        events.push(JsonEventSerializer::new(Vec::new()));
                    }
                }

                if events.len() == 1 && id.is_some() {
                    Ok(JsonResponse::new(json!({
                            "data": events.into_iter().next().unwrap(),
                    }))
                    .into_http_response())
                } else {
                    Ok(JsonResponse::new(json!({
                            "data": events,
                    }))
                    .into_http_response())
                }
            }
            ("live", Some("token"), &Method::GET) => {
                // Issue a live tracing token valid for 60 seconds

                Ok(JsonResponse::new(json!({
                    "data": self.issue_custom_token(account_id, "live_tracing", "web", 60).await?,
            }))
            .into_http_response())
            }
            ("live", _, &Method::GET) => {
                let mut key_filters = AHashMap::new();
                let mut filter = None;

                for (key, value) in params.into_inner() {
                    if key == "filter" {
                        filter = value.into_owned().into();
                    } else if let Some(key) = Key::try_parse(key.to_ascii_lowercase().as_str()) {
                        key_filters.insert(key, value.into_owned());
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
                                            if (filter.is_none() && key_filters.is_empty())
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
                                                    if let Some(needle) = key_filters.get(key).or(filter.as_ref()) {
                                                        let matches = match value {
                                                            Value::Static(haystack) => haystack.contains(needle),
                                                            Value::String(haystack) => haystack.contains(needle),
                                                            Value::Timestamp(haystack) => {
                                                                DateTime::from_timestamp(*haystack as i64)
                                                                    .to_rfc3339()
                                                                    .contains(needle)
                                                            }
                                                            Value::Bool(true) => needle == "true",
                                                            Value::Bool(false) => needle == "false",
                                                            Value::Ipv4(haystack) => haystack.to_string().contains(needle),
                                                            Value::Ipv6(haystack) => haystack.to_string().contains(needle),
                                                            Value::Event(_) |
                                                            Value::Array(_) |
                                                            Value::UInt(_) |
                                                            Value::Int(_) |
                                                            Value::Float(_) |
                                                            Value::Duration(_) |
                                                            Value::Bytes(_) |
                                                            Value::None => false,
                                                        };

                                                        if matches {
                                                            matched_keys.insert(*key);
                                                            if filter.is_some() || matched_keys.len() == key_filters.len() {
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
                                            serde_json::to_string(
                                                &JsonEventSerializer::new(std::mem::take(&mut events))
                                                .with_description()
                                                .with_explanation()).unwrap_or_default()
                                        ))));

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
