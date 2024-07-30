/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{str::FromStr, time::Duration};

use ahash::{AHashMap, AHashSet};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap,
};
use trc::{subscriber::Interests, EventType, Level, TracingEvent};
use utils::config::{utils::ParseValue, Config};

#[derive(Debug)]
pub struct Tracer {
    pub id: String,
    pub interests: Interests,
    pub typ: TracerType,
    pub lossy: bool,
}

#[derive(Debug)]
pub enum TracerType {
    Console(ConsoleTracer),
    Log(LogTracer),
    Otel(OtelTracer),
    Webhook(WebhookTracer),
    Journal,
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
pub struct OtelTracer {
    pub endpoint: String,
    pub headers: AHashMap<String, String>,
    pub is_http: bool,
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
pub enum RotationStrategy {
    Daily,
    Hourly,
    Minutely,
    Never,
}

#[derive(Debug)]
pub struct Tracers {
    pub global_interests: Interests,
    pub custom_levels: AHashMap<EventType, Level>,
    pub tracers: Vec<Tracer>,
}

impl Tracers {
    pub fn parse(config: &mut Config) -> Self {
        // Parse custom logging levels
        let mut custom_levels = AHashMap::new();
        for event_name in config
            .sub_keys("tracing.level", "")
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
        let mut tracers: Vec<Tracer> = Vec::new();
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
                        TracerType::Log(LogTracer {
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
                "console" | "stdout" | "stderr" => TracerType::Console(ConsoleTracer {
                    ansi: config
                        .property_or_default(("tracer", id, "ansi"), "true")
                        .unwrap_or(true),
                    multiline: config
                        .property_or_default(("tracer", id, "multiline"), "true")
                        .unwrap_or(true),
                    buffered: config
                        .property_or_default(("tracer", id, "buffered"), "true")
                        .unwrap_or(true),
                }),
                "otel" | "open-telemetry" => {
                    match config
                        .value_require(("tracer", id, "transport"))
                        .unwrap_or_default()
                    {
                        "gprc" => TracerType::Otel(OtelTracer {
                            endpoint: config
                                .value(("tracer", id, "endpoint"))
                                .unwrap_or_default()
                                .to_string(),
                            headers: Default::default(),
                            is_http: false,
                        }),
                        "http" => {
                            if let Some(endpoint) = config
                                .value_require(("tracer", id, "endpoint"))
                                .map(|s| s.to_string())
                            {
                                let mut headers = AHashMap::new();
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

                                TracerType::Otel(OtelTracer {
                                    endpoint,
                                    headers,
                                    is_http: true,
                                })
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
                    if !tracers.iter().any(|t| matches!(t.typ, TracerType::Journal)) {
                        TracerType::Journal
                    } else {
                        config.new_build_error(
                            ("tracer", id, "type"),
                            "Only one journal tracer is allowed".to_string(),
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
            let mut tracer = Tracer {
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
            let mut disabled_events = AHashSet::new();
            match &tracer.typ {
                TracerType::Console(_) => (),
                TracerType::Log(_) => {
                    disabled_events.insert(EventType::Tracing(TracingEvent::LogError));
                }
                TracerType::Otel(_) => {
                    disabled_events.insert(EventType::Tracing(TracingEvent::OtelError));
                }
                TracerType::Webhook(_) => {
                    disabled_events.insert(EventType::Tracing(TracingEvent::WebhookError));
                }
                TracerType::Journal => {
                    disabled_events.insert(EventType::Tracing(TracingEvent::JournalError));
                }
            }
            for (_, event_type) in config.properties::<EventType>(("tracer", id, "disabled-events"))
            {
                disabled_events.insert(event_type);
            }

            // Build interests lists
            for event_type in EventType::variants() {
                if !disabled_events.contains(&event_type) {
                    let event_level = custom_levels
                        .get(&event_type)
                        .copied()
                        .unwrap_or(event_type.level());
                    if event_level <= level {
                        tracer.interests.set(event_type);
                        global_interests.set(event_type);
                    }
                }
            }
            if !tracer.interests.is_empty() {
                tracers.push(tracer);
            } else {
                config.new_build_warning(("tracer", "id"), "No events enabled for tracer");
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
        if tracers.is_empty() {
            for event_type in EventType::variants() {
                let event_level = custom_levels
                    .get(&event_type)
                    .copied()
                    .unwrap_or(event_type.level());
                if event_level <= Level::Info {
                    global_interests.set(event_type);
                }
            }

            tracers.push(Tracer {
                id: "default".to_string(),
                interests: global_interests.clone(),
                typ: TracerType::Console(ConsoleTracer {
                    ansi: true,
                    multiline: true,
                    buffered: true,
                }),
                lossy: false,
            });
        }

        Tracers {
            tracers,
            global_interests,
            custom_levels,
        }
    }
}

fn parse_webhook(
    config: &mut Config,
    id: &str,
    global_interests: &mut Interests,
) -> Option<Tracer> {
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
    let mut tracer = Tracer {
        id: format!("w_{id}"),
        interests: Default::default(),
        lossy: config
            .property_or_default(("webhook", id, "lossy"), "false")
            .unwrap_or(false),
        typ: TracerType::Webhook(WebhookTracer {
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
    let event_names = EventType::variants()
        .into_iter()
        .filter_map(|e| {
            if e != EventType::Tracing(TracingEvent::WebhookError) {
                Some((e, e.name()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for (_, event_type) in config.properties::<EventOrMany>(("webhook", id, "events")) {
        match event_type {
            EventOrMany::Event(event_type) => {
                if event_type != EventType::Tracing(TracingEvent::WebhookError) {
                    tracer.interests.set(event_type);
                    global_interests.set(event_type);
                }
            }
            EventOrMany::StartsWith(value) => {
                for (event_type, name) in event_names.iter() {
                    if name.starts_with(&value) {
                        tracer.interests.set(*event_type);
                        global_interests.set(*event_type);
                    }
                }
            }
            EventOrMany::EndsWith(value) => {
                for (event_type, name) in event_names.iter() {
                    if name.ends_with(&value) {
                        tracer.interests.set(*event_type);
                        global_interests.set(*event_type);
                    }
                }
            }
            EventOrMany::All => {
                for (event_type, _) in event_names.iter() {
                    tracer.interests.set(*event_type);
                    global_interests.set(*event_type);
                }
                break;
            }
        }
    }

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
