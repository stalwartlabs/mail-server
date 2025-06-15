/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{LONG_1Y_SLUMBER, config::telemetry::OtelTracer};
use ahash::AHashMap;
use mail_parser::DateTime;
use opentelemetry::{
    InstrumentationScope, Key, KeyValue, Value,
    logs::{AnyValue, Severity},
    trace::{SpanContext, SpanKind, Status, TraceFlags, TraceState},
};
use opentelemetry_sdk::{
    Resource,
    logs::{LogBatch, LogExporter, SdkLogRecord},
    trace::{SpanData, SpanEvents, SpanExporter, SpanLinks},
};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trc::{Event, EventDetails, Level, TelemetryEvent, ipc::subscriber::SubscriberBuilder};

const MAX_EVENTS: usize = 2048;

pub(crate) fn spawn_otel_tracer(builder: SubscriberBuilder, mut otel: OtelTracer) {
    let (_, mut rx) = builder.register();
    tokio::spawn(async move {
        let resource = Resource::builder()
            .with_service_name("stalwart")
            .with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
            .build();

        let instrumentation = InstrumentationScope::builder("stalwart")
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();

        otel.log_exporter.set_resource(&resource);
        otel.span_exporter.set_resource(&resource);

        let mut wakeup_time = LONG_1Y_SLUMBER;
        let mut next_delivery = Instant::now();

        let mut pending_logs = Vec::new();
        let mut pending_spans = Vec::new();

        let mut active_spans = AHashMap::new();

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(wakeup_time, rx.recv()).await;

            match event_or_timeout {
                Ok(Some(events)) => {
                    for event in events {
                        if otel.log_exporter_enable {
                            pending_logs.push(otel.build_log_record(&event));
                        }

                        if otel.span_exporter_enable {
                            if let Some(span) = event.inner.span.as_ref() {
                                let span_id = span.span_id().unwrap();
                                if !event.inner.typ.is_span_end() {
                                    let events =
                                        active_spans.entry(span_id).or_insert_with(Vec::new);
                                    if events.len() < MAX_EVENTS {
                                        events.push(event);
                                    }
                                } else if let Some(events) = active_spans.remove(&span_id) {
                                    pending_spans.push(build_span_data(
                                        span,
                                        &event,
                                        events.iter().chain(std::iter::once(&event)),
                                        &instrumentation,
                                    ));
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

            // Process events
            let mut next_retry = None;
            let now = Instant::now();
            if next_delivery <= now {
                if !pending_spans.is_empty() || !pending_logs.is_empty() {
                    next_delivery = now + otel.throttle;

                    if !pending_spans.is_empty() {
                        if let Err(err) = otel
                            .span_exporter
                            .export(std::mem::take(&mut pending_spans))
                            .await
                        {
                            trc::event!(
                                Telemetry(TelemetryEvent::OtelExporterError),
                                Details = "Failed to export spans",
                                Reason = err.to_string()
                            );
                        }
                    }

                    if !pending_logs.is_empty() {
                        let logs = pending_logs
                            .iter()
                            .map(|log| (log, &instrumentation))
                            .collect::<Vec<_>>();

                        if let Err(err) = otel.log_exporter.export(LogBatch::new(&logs)).await {
                            trc::event!(
                                Telemetry(TelemetryEvent::OtelExporterError),
                                Details = "Failed to export logs",
                                Reason = err.to_string()
                            );
                        }
                        pending_logs.clear();
                    }
                }
            } else if !pending_logs.is_empty() || !pending_spans.is_empty() {
                // Retry later
                let this_retry = next_delivery - now;
                match next_retry {
                    Some(next_retry) if this_retry >= next_retry => {}
                    _ => {
                        next_retry = Some(this_retry);
                    }
                }
            }
            wakeup_time = next_retry.unwrap_or(LONG_1Y_SLUMBER);
        }
    });
}

fn build_span_data<I, T>(
    start_span: &Event<EventDetails>,
    end_span: &Event<EventDetails>,
    span_events: I,
    instrumentation: &InstrumentationScope,
) -> SpanData
where
    I: IntoIterator<Item = T>,
    T: AsRef<Event<EventDetails>>,
{
    let span_id = start_span.span_id().unwrap();

    let mut events = SpanEvents::default();
    events.events = span_events
        .into_iter()
        .map(|event| {
            let event = event.as_ref();

            opentelemetry::trace::Event::new(
                event.inner.typ.name(),
                UNIX_EPOCH + Duration::from_secs(event.inner.timestamp),
                event.keys.iter().filter_map(build_key_value).collect(),
                0,
            )
        })
        .collect();

    SpanData {
        span_context: SpanContext::new(
            (span_id as u128).into(),
            span_id.into(),
            TraceFlags::default(),
            false,
            TraceState::default(),
        ),
        dropped_attributes_count: 0,
        parent_span_id: 0.into(),
        name: start_span.inner.typ.name().into(),
        start_time: UNIX_EPOCH + Duration::from_secs(start_span.inner.timestamp),
        end_time: UNIX_EPOCH + Duration::from_secs(end_span.inner.timestamp),
        attributes: start_span.keys.iter().filter_map(build_key_value).collect(),
        events,
        links: SpanLinks::default(),
        status: Status::default(),
        span_kind: SpanKind::Server,
        instrumentation_scope: instrumentation.clone(),
    }
}

impl OtelTracer {
    fn build_log_record(&self, event: &Event<EventDetails>) -> SdkLogRecord {
        use opentelemetry::logs::LogRecord;
        use opentelemetry::logs::Logger;

        let mut record = self.log_provider.create_log_record();
        record.set_event_name(event.inner.typ.name());
        record.set_severity_number(match event.inner.level {
            Level::Trace => Severity::Trace,
            Level::Debug => Severity::Debug,
            Level::Info => Severity::Info,
            Level::Warn => Severity::Warn,
            Level::Error => Severity::Error,
            Level::Disable => Severity::Error,
        });
        record.set_severity_text(event.inner.level.as_str());
        record.set_body(AnyValue::String(event.inner.typ.description().into()));
        record.set_timestamp(UNIX_EPOCH + Duration::from_secs(event.inner.timestamp));
        record.set_observed_timestamp(SystemTime::now());
        for (k, v) in &event.keys {
            record.add_attribute(k.name(), build_any_value(v));
        }
        record
    }
}

fn build_key_value(key_value: &(trc::Key, trc::Value)) -> Option<KeyValue> {
    (key_value.0 != trc::Key::SpanId).then(|| {
        KeyValue::new(
            build_key(&key_value.0),
            match &key_value.1 {
                trc::Value::String(v) => Value::String(v.to_string().into()),
                trc::Value::UInt(v) => Value::I64(*v as i64),
                trc::Value::Int(v) => Value::I64(*v),
                trc::Value::Float(v) => Value::F64(*v),
                trc::Value::Timestamp(v) => {
                    Value::String(DateTime::from_timestamp(*v as i64).to_rfc3339().into())
                }
                trc::Value::Duration(v) => Value::I64(*v as i64),
                trc::Value::Bytes(_) => Value::String("[binary data]".into()),
                trc::Value::Bool(v) => Value::Bool(*v),
                trc::Value::Ipv4(v) => Value::String(v.to_string().into()),
                trc::Value::Ipv6(v) => Value::String(v.to_string().into()),
                trc::Value::Event(_) => Value::String("[event data]".into()),
                trc::Value::Array(_) => Value::String("[array]".into()),
                trc::Value::None => Value::Bool(false),
            },
        )
    })
}

fn build_key(key: &trc::Key) -> Key {
    Key::from_static_str(key.name())
}

fn build_any_value(value: &trc::Value) -> AnyValue {
    match value {
        trc::Value::String(v) => AnyValue::String(v.to_string().into()),
        trc::Value::UInt(v) => AnyValue::Int(*v as i64),
        trc::Value::Int(v) => AnyValue::Int(*v),
        trc::Value::Float(v) => AnyValue::Double(*v),
        trc::Value::Timestamp(v) => {
            AnyValue::String(DateTime::from_timestamp(*v as i64).to_rfc3339().into())
        }
        trc::Value::Duration(v) => AnyValue::Int(*v as i64),
        trc::Value::Bytes(v) => AnyValue::Bytes(Box::new(v.clone())),
        trc::Value::Bool(v) => AnyValue::Boolean(*v),
        trc::Value::Ipv4(v) => AnyValue::String(v.to_string().into()),
        trc::Value::Ipv6(v) => AnyValue::String(v.to_string().into()),
        trc::Value::Event(v) => AnyValue::Map(Box::new(
            [(
                Key::from_static_str("eventName"),
                AnyValue::String(v.event_type().name().into()),
            )]
            .into_iter()
            .chain(
                v.keys()
                    .iter()
                    .map(|(k, v)| (build_key(k), build_any_value(v))),
            )
            .collect(),
        )),
        trc::Value::Array(v) => {
            AnyValue::ListAny(Box::new(v.iter().map(build_any_value).collect()))
        }
        trc::Value::None => AnyValue::Boolean(false),
    }
}
