/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use std::time::Duration;

use store::{Store, Stores};
use trc::{EventType, MetricType, TOTAL_EVENT_COUNT};
use utils::config::{
    cron::SimpleCron,
    utils::{AsKey, ParseValue},
    Config,
};

use crate::{
    expr::{tokenizer::TokenMap, Expression},
    total_accounts,
};

use super::{
    license::LicenseValidator, AlertContent, AlertContentToken, AlertMethod, Enterprise,
    MetricAlert, MetricStore, TraceStore, Undelete,
};

impl Enterprise {
    pub async fn parse(config: &mut Config, stores: &Stores, data: &Store) -> Option<Self> {
        let license = match LicenseValidator::new()
            .try_parse(config.value("enterprise.license-key")?)
            .and_then(|key| {
                key.into_validated_key(config.value("lookup.default.hostname").unwrap_or_default())
            }) {
            Ok(key) => key,
            Err(err) => {
                config.new_build_warning("enterprise.license-key", err.to_string());
                return None;
            }
        };

        match total_accounts(data).await {
            Ok(total) if total > license.accounts as u64 => {
                config.new_build_warning(
                    "enterprise.license-key",
                    format!(
                        "License key is valid but only allows {} accounts, found {}.",
                        license.accounts, total
                    ),
                );
                return None;
            }
            Err(e) => {
                if !matches!(data, Store::None) {
                    config.new_build_error("enterprise.license-key", e.to_string());
                }
                return None;
            }
            _ => (),
        }

        let trace_store = if config
            .property_or_default("tracing.history.enable", "false")
            .unwrap_or(false)
        {
            if let Some(store) = config
                .value("tracing.history.store")
                .and_then(|name| stores.stores.get(name))
                .cloned()
            {
                TraceStore {
                    retention: config
                        .property_or_default::<Option<Duration>>("tracing.history.retention", "30d")
                        .unwrap_or(Some(Duration::from_secs(30 * 24 * 60 * 60))),
                    store,
                }
                .into()
            } else {
                None
            }
        } else {
            None
        };
        let metrics_store = if config
            .property_or_default("metrics.history.enable", "false")
            .unwrap_or(false)
        {
            if let Some(store) = config
                .value("metrics.history.store")
                .and_then(|name| stores.stores.get(name))
                .cloned()
            {
                MetricStore {
                    retention: config
                        .property_or_default::<Option<Duration>>("metrics.history.retention", "90d")
                        .unwrap_or(Some(Duration::from_secs(90 * 24 * 60 * 60))),
                    store,
                    interval: config
                        .property_or_default::<SimpleCron>("metrics.history.interval", "0 * *")
                        .unwrap_or_else(|| SimpleCron::parse_value("0 * *").unwrap()),
                }
                .into()
            } else {
                None
            }
        } else {
            None
        };

        Some(Enterprise {
            license,
            undelete: config
                .property_or_default::<Option<Duration>>("storage.undelete.retention", "false")
                .unwrap_or_default()
                .map(|retention| Undelete { retention }),
            trace_store,
            metrics_store,
            metrics_alerts: parse_metric_alerts(config),
        })
    }
}

pub fn parse_metric_alerts(config: &mut Config) -> Vec<MetricAlert> {
    let mut alerts = Vec::new();

    for metric_id in config
        .sub_keys("metrics.alerts", ".enable")
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
    {
        if let Some(alert) = parse_metric_alert(config, metric_id) {
            alerts.push(alert);
        }
    }

    alerts
}

fn parse_metric_alert(config: &mut Config, id: String) -> Option<MetricAlert> {
    if !config.property_or_default::<bool>(("metrics.alerts", id.as_str(), "enable"), "false")? {
        return None;
    }

    let mut alert = MetricAlert {
        condition: Expression::try_parse(
            config,
            ("metrics.alerts", id.as_str(), "condition"),
            &TokenMap::default().with_variables_map(
                EventType::variants()
                    .into_iter()
                    .map(|e| (sanitize_metric_name(e.name()), e.id() as u32))
                    .chain(MetricType::variants().iter().map(|m| {
                        (
                            sanitize_metric_name(m.name()),
                            m.code() as u32 + TOTAL_EVENT_COUNT as u32,
                        )
                    })),
            ),
        )?,
        method: Vec::new(),
        id,
    };
    let id_str = alert.id.as_str();

    if config
        .property_or_default::<bool>(("metrics.alerts", id_str, "notify.event.enable"), "false")
        .unwrap_or_default()
    {
        alert.method.push(AlertMethod::Event {
            message: parse_alert_content(
                ("metrics.alerts", id_str, "notify.event.message"),
                config,
            ),
        });
    }

    if config
        .property_or_default::<bool>(("metrics.alerts", id_str, "notify.email.enable"), "false")
        .unwrap_or_default()
    {
        let from_addr = config
            .value_require(("metrics.alerts", id_str, "notify.email.from-addr"))?
            .trim()
            .to_string();
        let from_name = config
            .value(("metrics.alerts", id_str, "notify.email.from-name"))
            .map(|s| s.to_string());
        let to = config
            .values(("metrics.alerts", id_str, "notify.email.to"))
            .filter_map(|(_, s)| {
                if s.contains('@') {
                    s.trim().to_string().into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let subject =
            parse_alert_content(("metrics.alerts", id_str, "notify.email.subject"), config)?;
        let body = parse_alert_content(("metrics.alerts", id_str, "notify.email.body"), config)?;

        if !from_addr.contains('@') {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.from-addr"),
                "Invalid from email address",
            );
        }
        if to.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.to"),
                "Missing recipient address(es)",
            );
        }
        if subject.0.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.subject"),
                "Missing email subject",
            );
        }
        if body.0.is_empty() {
            config.new_build_error(
                ("metrics.alerts", id_str, "notify.email.body"),
                "Missing email body",
            );
        }

        alert.method.push(AlertMethod::Email {
            from_name,
            from_addr,
            to,
            subject,
            body,
        });
    }

    if alert.method.is_empty() {
        config.new_build_error(
            ("metrics.alerts", id_str),
            "No notification method enabled for alert",
        );
    }

    alert.into()
}

fn parse_alert_content(key: impl AsKey, config: &mut Config) -> Option<AlertContent> {
    let mut tokens = Vec::new();
    let mut value = config.value(key)?.chars().peekable();
    let mut buf = String::new();

    while let Some(ch) = value.next() {
        if ch == '%' && value.peek() == Some(&'{') {
            value.next();

            let mut var_name = String::new();
            let mut found_curly = false;

            for ch in value.by_ref() {
                if ch == '}' {
                    found_curly = true;
                    break;
                }
                var_name.push(ch);
            }

            if found_curly && value.peek() == Some(&'%') {
                value.next();
                if let Some(event_type) = EventType::try_parse(&var_name)
                    .map(AlertContentToken::Event)
                    .or_else(|| MetricType::try_parse(&var_name).map(AlertContentToken::Metric))
                {
                    if !buf.is_empty() {
                        tokens.push(AlertContentToken::Text(std::mem::take(&mut buf)));
                    }
                    tokens.push(event_type);
                } else {
                    buf.push('%');
                    buf.push('{');
                    buf.push_str(&var_name);
                    buf.push('}');
                    buf.push('%');
                }
            } else {
                buf.push('%');
                buf.push('{');
                buf.push_str(&var_name);
            }
        } else {
            buf.push(ch);
        }
    }

    if !buf.is_empty() {
        tokens.push(AlertContentToken::Text(buf));
    }

    AlertContent(tokens).into()
}

fn sanitize_metric_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            result.push(ch);
        } else {
            result.push('_');
        }
    }

    result
}
