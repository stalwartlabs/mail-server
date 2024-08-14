/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap,
};
use opentelemetry::{InstrumentationLibrary, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    export::{logs::LogExporter, trace::SpanExporter},
    metrics::{
        exporter::PushMetricsExporter,
        reader::{DefaultAggregationSelector, DefaultTemporalitySelector},
    },
    Resource,
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use store::Stores;
use trc::{ipc::subscriber::Interests, EventType, Level, TelemetryEvent};
use utils::config::{utils::ParseValue, Config};

#[derive(Debug)]
pub struct TelemetrySubscriber {
    pub id: String,
    pub interests: Interests,
    pub typ: TelemetrySubscriberType,
    pub lossy: bool,
}

#[derive(Debug)]
pub enum TelemetrySubscriberType {
    ConsoleTracer(ConsoleTracer),
    LogTracer(LogTracer),
    OtelTracer(OtelTracer),
    Webhook(WebhookTracer),
    #[cfg(unix)]
    JournalTracer(crate::telemetry::tracers::journald::Subscriber),
    #[cfg(feature = "enterprise")]
    StoreTracer(StoreTracer),
}

#[derive(Debug)]
pub struct OtelTracer {
    pub span_exporter: Box<dyn SpanExporter>,
    pub span_exporter_enable: bool,
    pub log_exporter: Box<dyn LogExporter>,
    pub log_exporter_enable: bool,
    pub throttle: Duration,
}

pub struct OtelMetrics {
    pub resource: Resource,
    pub instrumentation: InstrumentationLibrary,
    pub exporter: Box<dyn PushMetricsExporter>,
    pub interval: Duration,
}

#[derive(Debug)]
pub struct ConsoleTracer {
    pub ansi: bool,
    pub multiline: bool,
    pub buffered: bool,
}

#[derive(Debug)]
pub struct LogTracer {
    pub path: String,
    pub prefix: String,
    pub rotate: RotationStrategy,
    pub ansi: bool,
    pub multiline: bool,
}

#[derive(Debug)]
pub struct WebhookTracer {
    pub url: String,
    pub key: String,
    pub timeout: Duration,
    pub throttle: Duration,
    pub discard_after: Duration,
    pub tls_allow_invalid_certs: bool,
    pub headers: HeaderMap,
}

#[derive(Debug)]
#[cfg(feature = "enterprise")]
pub struct StoreTracer {
    pub store: store::Store,
}

#[derive(Debug)]
pub enum RotationStrategy {
    Daily,
    Hourly,
    Minutely,
    Never,
}

#[derive(Debug)]
pub struct Telemetry {
    pub tracers: Tracers,
    pub metrics: Interests,
}

#[derive(Debug)]
pub struct Tracers {
    pub interests: Interests,
    pub levels: AHashMap<EventType, Level>,
    pub subscribers: Vec<TelemetrySubscriber>,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub prometheus: Option<PrometheusMetrics>,
    pub otel: Option<Arc<OtelMetrics>>,
}

#[derive(Debug, Clone, Default)]
pub struct PrometheusMetrics {
    pub auth: Option<String>,
}

impl Telemetry {
    pub fn parse(config: &mut Config, stores: &Stores) -> Self {
        let mut telemetry = Telemetry {
            tracers: Tracers::parse(config, stores),
            metrics: Interests::default(),
        };

        // Parse metrics
        if config
            .property_or_default("metrics.prometheus.enable", "false")
            .unwrap_or(false)
            || ["http", "grpc"].contains(
                &config
                    .value("metrics.open-telemetry.transport")
                    .unwrap_or("disabled"),
            )
        {
            apply_events(
                config
                    .properties::<EventOrMany>("metrics.disabled-events")
                    .into_iter()
                    .map(|(_, e)| e),
                false,
                |event_type| {
                    if event_type.is_metric() {
                        telemetry.metrics.set(event_type);
                    }
                },
            );
        }

        telemetry
    }
}

impl Tracers {
    pub fn parse(config: &mut Config, stores: &Stores) -> Self {
        // Parse custom logging levels
        let mut custom_levels = AHashMap::new();
        for event_name in config
            .prefix("tracing.level")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            if let Some(event_type) =
                config.try_parse_value::<EventType>(("tracing.level", &event_name), &event_name)
            {
                if let Some(level) =
                    config.property_require::<Level>(("tracing.level", &event_name))
                {
                    custom_levels.insert(event_type, level);
                }
            }
        }

        // Parse tracers
        let mut tracers: Vec<TelemetrySubscriber> = Vec::new();
        let mut global_interests = Interests::default();
        for tracer_id in config
            .sub_keys("tracer", ".type")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            let id = tracer_id.as_str();

            // Skip disabled tracers
            if !config
                .property::<bool>(("tracer", id, "enable"))
                .unwrap_or(true)
            {
                continue;
            }

            // Parse tracer
            let typ = match config
                .value(("tracer", id, "type"))
                .unwrap_or_default()
                .to_string()
                .as_str()
            {
                "log" => {
                    if let Some(path) = config
                        .value_require(("tracer", id, "path"))
                        .map(|s| s.to_string())
                    {
                        TelemetrySubscriberType::LogTracer(LogTracer {
                            path,
                            prefix: config
                                .value(("tracer", id, "prefix"))
                                .unwrap_or("stalwart")
                                .to_string(),
                            rotate: match config.value(("tracer", id, "rotate")).unwrap_or("daily")
                            {
                                "daily" => RotationStrategy::Daily,
                                "hourly" => RotationStrategy::Hourly,
                                "minutely" => RotationStrategy::Minutely,
                                "never" => RotationStrategy::Never,
                                rotate => {
                                    let err = format!("Invalid rotation strategy: {rotate}");
                                    config.new_parse_error(("tracer", id, "rotate"), err);
                                    RotationStrategy::Daily
                                }
                            },
                            ansi: config
                                .property_or_default(("tracer", id, "ansi"), "false")
                                .unwrap_or(false),
                            multiline: config
                                .property_or_default(("tracer", id, "multiline"), "false")
                                .unwrap_or(false),
                        })
                    } else {
                        continue;
                    }
                }
                "console" | "stdout" | "stderr" => {
                    if !tracers
                        .iter()
                        .any(|t| matches!(t.typ, TelemetrySubscriberType::ConsoleTracer(_)))
                    {
                        TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                            ansi: config
                                .property_or_default(("tracer", id, "ansi"), "true")
                                .unwrap_or(true),
                            multiline: config
                                .property_or_default(("tracer", id, "multiline"), "false")
                                .unwrap_or(false),
                            buffered: config
                                .property_or_default(("tracer", id, "buffered"), "true")
                                .unwrap_or(true),
                        })
                    } else {
                        config.new_build_error(
                            ("tracer", id, "type"),
                            "Only one console tracer is allowed".to_string(),
                        );
                        continue;
                    }
                }
                "otel" | "open-telemetry" => {
                    let timeout = config
                        .property::<Duration>(("tracer", id, "timeout"))
                        .unwrap_or(Duration::from_secs(
                            opentelemetry_otlp::OTEL_EXPORTER_OTLP_TIMEOUT_DEFAULT,
                        ));
                    let throttle = config
                        .property_or_default(("tracer", id, "throttle"), "1s")
                        .unwrap_or_else(|| Duration::from_secs(1));
                    let log_exporter_enable = config
                        .property_or_default(("tracer", id, "enable.log-exporter"), "true")
                        .unwrap_or(true);
                    let span_exporter_enable = config
                        .property_or_default(("tracer", id, "enable.span-exporter"), "true")
                        .unwrap_or(true);

                    match config
                        .value_require(("tracer", id, "transport"))
                        .unwrap_or_default()
                    {
                        "grpc" => {
                            let mut span_exporter = opentelemetry_otlp::new_exporter()
                                .tonic()
                                .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                                .with_timeout(timeout);
                            let mut log_exporter = opentelemetry_otlp::new_exporter()
                                .tonic()
                                .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                                .with_timeout(timeout);
                            if let Some(endpoint) = config.value(("tracer", id, "endpoint")) {
                                span_exporter = span_exporter.with_endpoint(endpoint);
                                log_exporter = log_exporter.with_endpoint(endpoint);
                            }

                            match (
                                span_exporter.build_span_exporter(),
                                log_exporter.build_log_exporter(),
                            ) {
                                (Ok(span_exporter), Ok(log_exporter)) => {
                                    TelemetrySubscriberType::OtelTracer(OtelTracer {
                                        span_exporter: Box::new(span_exporter),
                                        log_exporter: Box::new(log_exporter),
                                        throttle,
                                        span_exporter_enable,
                                        log_exporter_enable,
                                    })
                                }
                                (Err(err), _) => {
                                    config.new_build_error(
                                        ("tracer", id),
                                        format!(
                                            "Failed to build OpenTelemetry span exporter: {err}"
                                        ),
                                    );
                                    continue;
                                }
                                (_, Err(err)) => {
                                    config.new_build_error(
                                        ("tracer", id),
                                        format!(
                                            "Failed to build OpenTelemetry log exporter: {err}"
                                        ),
                                    );
                                    continue;
                                }
                            }
                        }
                        "http" => {
                            if let Some(endpoint) = config
                                .value_require(("tracer", id, "endpoint"))
                                .map(|s| s.to_string())
                            {
                                let mut headers = HashMap::new();
                                let mut err = None;
                                for (_, value) in config.values(("tracer", id, "headers")) {
                                    if let Some((key, value)) = value.split_once(':') {
                                        headers.insert(
                                            key.trim().to_string(),
                                            value.trim().to_string(),
                                        );
                                    } else {
                                        err = format!("Invalid open-telemetry header {value:?}")
                                            .into();
                                        break;
                                    }
                                }
                                if let Some(err) = err {
                                    config.new_parse_error(("tracer", id, "headers"), err);
                                }

                                let mut span_exporter = opentelemetry_otlp::new_exporter()
                                    .http()
                                    .with_endpoint(&endpoint)
                                    .with_timeout(timeout);
                                let mut log_exporter = opentelemetry_otlp::new_exporter()
                                    .http()
                                    .with_endpoint(&endpoint)
                                    .with_timeout(timeout);
                                if !headers.is_empty() {
                                    span_exporter = span_exporter.with_headers(headers.clone());
                                    log_exporter = log_exporter.with_headers(headers);
                                }

                                match (
                                    span_exporter.build_span_exporter(),
                                    log_exporter.build_log_exporter(),
                                ) {
                                    (Ok(span_exporter), Ok(log_exporter)) => {
                                        TelemetrySubscriberType::OtelTracer(OtelTracer {
                                            span_exporter: Box::new(span_exporter),
                                            log_exporter: Box::new(log_exporter),
                                            throttle,
                                            span_exporter_enable,
                                            log_exporter_enable,
                                        })
                                    }
                                    (Err(err), _) => {
                                        config.new_build_error(
                                            ("tracer", id),
                                            format!(
                                                "Failed to build OpenTelemetry span exporter: {err}"
                                            ),
                                        );
                                        continue;
                                    }
                                    (_, Err(err)) => {
                                        config.new_build_error(
                                            ("tracer", id),
                                            format!(
                                                "Failed to build OpenTelemetry log exporter: {err}"
                                            ),
                                        );
                                        continue;
                                    }
                                }
                            } else {
                                continue;
                            }
                        }
                        transport => {
                            let err = format!("Invalid transport: {transport}");
                            config.new_parse_error(("tracer", id, "transport"), err);
                            continue;
                        }
                    }
                }
                "journal" => {
                    #[cfg(unix)]
                    {
                        if !tracers
                            .iter()
                            .any(|t| matches!(t.typ, TelemetrySubscriberType::JournalTracer(_)))
                        {
                            match crate::telemetry::tracers::journald::Subscriber::new() {
                                Ok(subscriber) => {
                                    TelemetrySubscriberType::JournalTracer(subscriber)
                                }
                                Err(e) => {
                                    config.new_build_error(
                                        ("tracer", id, "type"),
                                        format!("Failed to create journald subscriber: {e}"),
                                    );
                                    continue;
                                }
                            }
                        } else {
                            config.new_build_error(
                                ("tracer", id, "type"),
                                "Only one journal tracer is allowed".to_string(),
                            );
                            continue;
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        config.new_build_error(
                            ("tracer", id, "type"),
                            "Journald is only available on Unix systems.",
                        );
                        continue;
                    }
                }
                unknown => {
                    config.new_parse_error(
                        ("tracer", id, "type"),
                        format!("Unknown tracer type: {unknown}"),
                    );
                    continue;
                }
            };

            // Create tracer
            let mut tracer = TelemetrySubscriber {
                id: format!("t_{id}"),
                interests: Default::default(),
                lossy: config
                    .property_or_default(("tracer", id, "lossy"), "false")
                    .unwrap_or(false),
                typ,
            };

            // Parse level
            let level = Level::from_str(config.value(("tracer", id, "level")).unwrap_or("info"))
                .map_err(|err| {
                    config.new_parse_error(
                        ("tracer", id, "level"),
                        format!("Invalid log level: {err}"),
                    )
                })
                .unwrap_or(Level::Info);

            // Parse disabled events
            let exclude_event = match &tracer.typ {
                TelemetrySubscriberType::ConsoleTracer(_) => None,
                TelemetrySubscriberType::LogTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::LogError).into()
                }
                TelemetrySubscriberType::OtelTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::OtelExpoterError).into()
                }
                TelemetrySubscriberType::Webhook(_) => {
                    EventType::Telemetry(TelemetryEvent::WebhookError).into()
                }
                #[cfg(unix)]
                TelemetrySubscriberType::JournalTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::JournalError).into()
                }
                #[cfg(feature = "enterprise")]
                TelemetrySubscriberType::StoreTracer(_) => None,
            };

            // Parse disabled events
            apply_events(
                config
                    .properties::<EventOrMany>(("tracer", id, "disabled-events"))
                    .into_iter()
                    .map(|(_, e)| e),
                false,
                |event_type| {
                    if exclude_event != Some(event_type) {
                        let event_level = custom_levels
                            .get(&event_type)
                            .copied()
                            .unwrap_or(event_type.level());
                        if level.is_contained(event_level) {
                            tracer.interests.set(event_type);
                            global_interests.set(event_type);
                        }
                    }
                },
            );

            if !tracer.interests.is_empty() {
                tracers.push(tracer);
            } else {
                config.new_build_warning(("tracer", "id"), "No events enabled for tracer");
            }
        }

        // Parse tracing history
        #[cfg(feature = "enterprise")]
        {
            if config
                .property_or_default("tracing.history.enable", "false")
                .unwrap_or(false)
            {
                if let Some(store_id) = config.value_require("tracing.history.store") {
                    if let Some(store) = stores.stores.get(store_id) {
                        let mut tracer = TelemetrySubscriber {
                            id: "history".to_string(),
                            interests: Default::default(),
                            lossy: false,
                            typ: TelemetrySubscriberType::StoreTracer(StoreTracer {
                                store: store.clone(),
                            }),
                        };

                        for event_type in StoreTracer::default_events() {
                            tracer.interests.set(event_type);
                            global_interests.set(event_type);
                        }

                        tracers.push(tracer);
                    } else {
                        let err = format!("Store {store_id} not found");
                        config.new_build_error("tracing.history.store", err);
                    }
                }
            }
        }

        // Parse webhooks
        for id in config
            .sub_keys("webhook", ".url")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            if let Some(webhook) = parse_webhook(config, &id, &mut global_interests) {
                tracers.push(webhook);
            }
        }

        // Add default tracer if none were found
        #[cfg(not(feature = "test_mode"))]
        if tracers.is_empty() {
            for event_type in EventType::variants() {
                let event_level = custom_levels
                    .get(&event_type)
                    .copied()
                    .unwrap_or(event_type.level());
                if Level::Info.is_contained(event_level) {
                    global_interests.set(event_type);
                }
            }

            tracers.push(TelemetrySubscriber {
                id: "default".to_string(),
                interests: global_interests.clone(),
                typ: TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                    ansi: true,
                    multiline: false,
                    buffered: true,
                }),
                lossy: false,
            });
        }

        Tracers {
            subscribers: tracers,
            interests: global_interests,
            levels: custom_levels,
        }
    }
}

impl Metrics {
    pub fn parse(config: &mut Config) -> Self {
        let mut metrics = Metrics {
            prometheus: None,
            otel: None,
        };

        if config
            .property_or_default("metrics.prometheus.enable", "false")
            .unwrap_or(false)
        {
            metrics.prometheus = Some(PrometheusMetrics {
                auth: config
                    .value("metrics.prometheus.auth.username")
                    .and_then(|user| {
                        config
                            .value("metrics.prometheus.auth.secret")
                            .map(|secret| STANDARD.encode(format!("{user}:{secret}")))
                    }),
            });
        }

        let otel_enabled = match config
            .value("metrics.open-telemetry.transport")
            .unwrap_or("disable")
        {
            "grpc" => true.into(),
            "http" | "https" => false.into(),
            "disable" | "disabled" => None,
            transport => {
                let err = format!("Invalid transport: {transport}");
                config.new_parse_error("metrics.open-telemetry.transport", err);
                None
            }
        };

        if let Some(is_grpc) = otel_enabled {
            let timeout = config
                .property::<Duration>("metrics.open-telemetry.timeout")
                .unwrap_or(Duration::from_secs(
                    opentelemetry_otlp::OTEL_EXPORTER_OTLP_TIMEOUT_DEFAULT,
                ));
            let interval = config
                .property_or_default("metrics.open-telemetry.interval", "1m")
                .unwrap_or_else(|| Duration::from_secs(60));
            let resource = Resource::new([
                KeyValue::new(SERVICE_NAME, "stalwart-mail"),
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            ]);
            let instrumentation = InstrumentationLibrary::builder("stalwart-mail")
                .with_version(env!("CARGO_PKG_VERSION"))
                .build();

            if is_grpc {
                let mut exporter = opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                    .with_timeout(timeout);
                if let Some(endpoint) = config.value("metrics.open-telemetry.endpoint") {
                    exporter = exporter.with_endpoint(endpoint);
                }

                match exporter.build_metrics_exporter(
                    Box::new(DefaultAggregationSelector::new()),
                    Box::new(DefaultTemporalitySelector::new()),
                ) {
                    Ok(exporter) => {
                        metrics.otel = Some(Arc::new(OtelMetrics {
                            exporter: Box::new(exporter),
                            interval,
                            resource,
                            instrumentation,
                        }));
                    }
                    Err(err) => {
                        config.new_build_error(
                            "metrics.open-telemetry",
                            format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                        );
                    }
                }
            } else if let Some(endpoint) = config
                .value_require("metrics.open-telemetry.endpoint")
                .map(|s| s.to_string())
            {
                let mut headers = HashMap::new();
                let mut err = None;
                for (_, value) in config.values("metrics.open-telemetry.headers") {
                    if let Some((key, value)) = value.split_once(':') {
                        headers.insert(key.trim().to_string(), value.trim().to_string());
                    } else {
                        err = format!("Invalid open-telemetry header {value:?}").into();
                        break;
                    }
                }
                if let Some(err) = err {
                    config.new_parse_error("metrics.open-telemetry.headers", err);
                }

                let mut exporter = opentelemetry_otlp::new_exporter()
                    .http()
                    .with_endpoint(&endpoint)
                    .with_timeout(timeout);
                if !headers.is_empty() {
                    exporter = exporter.with_headers(headers);
                }

                match exporter.build_metrics_exporter(
                    Box::new(DefaultAggregationSelector::new()),
                    Box::new(DefaultTemporalitySelector::new()),
                ) {
                    Ok(exporter) => {
                        metrics.otel = Some(Arc::new(OtelMetrics {
                            exporter: Box::new(exporter),
                            interval,
                            resource,
                            instrumentation,
                        }));
                    }
                    Err(err) => {
                        config.new_build_error(
                            "metrics.open-telemetry",
                            format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                        );
                    }
                }
            }
        }

        metrics
    }
}

fn parse_webhook(
    config: &mut Config,
    id: &str,
    global_interests: &mut Interests,
) -> Option<TelemetrySubscriber> {
    let mut headers = HeaderMap::new();

    for (header, value) in config
        .values(("webhook", id, "headers"))
        .map(|(_, v)| {
            if let Some((k, v)) = v.split_once(':') {
                Ok((
                    HeaderName::from_str(k.trim()).map_err(|err| {
                        format!("Invalid header found in property \"webhook.{id}.headers\": {err}",)
                    })?,
                    HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!("Invalid header found in property \"webhook.{id}.headers\": {err}",)
                    })?,
                ))
            } else {
                Err(format!(
                    "Invalid header found in property \"webhook.{id}.headers\": {v}",
                ))
            }
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()
        .map_err(|e| config.new_parse_error(("webhook", id, "headers"), e))
        .unwrap_or_default()
    {
        headers.insert(header, value);
    }

    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    if let (Some(name), Some(secret)) = (
        config.value(("webhook", id, "auth.username")),
        config.value(("webhook", id, "auth.secret")),
    ) {
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{}:{}", name, secret)))
                .parse()
                .unwrap(),
        );
    }

    // Build tracer
    let mut tracer = TelemetrySubscriber {
        id: format!("w_{id}"),
        interests: Default::default(),
        lossy: config
            .property_or_default(("webhook", id, "lossy"), "false")
            .unwrap_or(false),
        typ: TelemetrySubscriberType::Webhook(WebhookTracer {
            url: config.value_require(("webhook", id, "url"))?.to_string(),
            timeout: config
                .property_or_default(("webhook", id, "timeout"), "30s")
                .unwrap_or_else(|| Duration::from_secs(30)),
            tls_allow_invalid_certs: config
                .property_or_default(("webhook", id, "allow-invalid-certs"), "false")
                .unwrap_or_default(),
            headers,
            key: config
                .value(("webhook", id, "signature-key"))
                .unwrap_or_default()
                .to_string(),
            throttle: config
                .property_or_default(("webhook", id, "throttle"), "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            discard_after: config
                .property_or_default(("webhook", id, "discard-after"), "5m")
                .unwrap_or_else(|| Duration::from_secs(300)),
        }),
    };

    // Parse webhook events
    apply_events(
        config
            .properties::<EventOrMany>(("webhook", id, "events"))
            .into_iter()
            .map(|(_, e)| e),
        true,
        |event_type| {
            if event_type != EventType::Telemetry(TelemetryEvent::WebhookError) {
                tracer.interests.set(event_type);
                global_interests.set(event_type);
            }
        },
    );

    if !tracer.interests.is_empty() {
        Some(tracer)
    } else {
        config.new_build_warning(("webhook", id), "No events enabled for webhook");
        None
    }
}

enum EventOrMany {
    Event(EventType),
    StartsWith(String),
    EndsWith(String),
    All,
}

fn apply_events(
    event_types: impl IntoIterator<Item = EventOrMany>,
    inclusive: bool,
    mut apply_fn: impl FnMut(EventType),
) {
    let event_names = EventType::variants()
        .into_iter()
        .map(|e| (e, e.name()))
        .collect::<Vec<_>>();
    let mut exclude_events = AHashSet::new();

    for event_or_many in event_types {
        match event_or_many {
            EventOrMany::Event(event_type) => {
                if inclusive {
                    apply_fn(event_type);
                } else {
                    exclude_events.insert(event_type);
                }
            }
            EventOrMany::StartsWith(value) => {
                for (event_type, name) in event_names.iter() {
                    if name.starts_with(&value) {
                        if inclusive {
                            apply_fn(*event_type);
                        } else {
                            exclude_events.insert(*event_type);
                        }
                    }
                }
            }
            EventOrMany::EndsWith(value) => {
                for (event_type, name) in event_names.iter() {
                    if name.ends_with(&value) {
                        if inclusive {
                            apply_fn(*event_type);
                        } else {
                            exclude_events.insert(*event_type);
                        }
                    }
                }
            }
            EventOrMany::All => {
                for (event_type, _) in event_names.iter() {
                    if inclusive {
                        apply_fn(*event_type);
                    } else {
                        exclude_events.insert(*event_type);
                    }
                }
                break;
            }
        }
    }

    if !inclusive {
        for (event_type, _) in event_names.iter() {
            if !exclude_events.contains(event_type) {
                apply_fn(*event_type);
            }
        }
    }
}

impl ParseValue for EventOrMany {
    fn parse_value(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value == "*" {
            Ok(EventOrMany::All)
        } else if let Some(suffix) = value.strip_prefix("*") {
            Ok(EventOrMany::EndsWith(suffix.to_string()))
        } else if let Some(prefix) = value.strip_suffix("*") {
            Ok(EventOrMany::StartsWith(prefix.to_string()))
        } else {
            EventType::parse_value(value).map(EventOrMany::Event)
        }
    }
}

impl std::fmt::Debug for OtelMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelMetrics")
            .field("interval", &self.interval)
            .finish()
    }
}
