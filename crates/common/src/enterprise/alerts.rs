/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use mail_builder::{
    headers::{
        address::{Address, EmailAddress},
        HeaderType,
    },
    MessageBuilder,
};
use trc::{Collector, MetricType, TelemetryEvent, TOTAL_EVENT_COUNT};

use super::{AlertContent, AlertContentToken, AlertMethod};
use crate::{
    expr::{functions::ResolveVariable, Variable},
    Core,
};
use std::fmt::Write;

#[derive(Debug, PartialEq, Eq)]
pub struct AlertMessage {
    pub from: String,
    pub to: Vec<String>,
    pub body: Vec<u8>,
}

struct CollectorResolver;

impl Core {
    pub async fn process_alerts(&self) -> Option<Vec<AlertMessage>> {
        let alerts = &self.enterprise.as_ref()?.metrics_alerts;
        if alerts.is_empty() {
            return None;
        }
        let mut messages = Vec::new();

        for alert in alerts {
            if !self
                .eval_expr(&alert.condition, &CollectorResolver, &alert.id, 0)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            for method in &alert.method {
                match method {
                    AlertMethod::Email {
                        from_name,
                        from_addr,
                        to,
                        subject,
                        body,
                    } => {
                        messages.push(AlertMessage {
                            from: from_addr.clone(),
                            to: to.clone(),
                            body: MessageBuilder::new()
                                .from(Address::Address(EmailAddress {
                                    name: from_name.as_ref().map(|s| s.into()),
                                    email: from_addr.as_str().into(),
                                }))
                                .header(
                                    "To",
                                    HeaderType::Address(Address::List(
                                        to.iter()
                                            .map(|to| {
                                                Address::Address(EmailAddress {
                                                    name: None,
                                                    email: to.as_str().into(),
                                                })
                                            })
                                            .collect(),
                                    )),
                                )
                                .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
                                .subject(subject.build())
                                .text_body(body.build())
                                .write_to_vec()
                                .unwrap_or_default(),
                        });
                    }
                    AlertMethod::Event { message } => {
                        trc::event!(
                            Telemetry(TelemetryEvent::Alert),
                            Id = alert.id.to_string(),
                            Details = message.as_ref().map(|m| m.build())
                        );

                        #[cfg(feature = "test_mode")]
                        Collector::update_event_counter(
                            trc::EventType::Telemetry(TelemetryEvent::Alert),
                            1,
                        );
                    }
                }
            }
        }

        (!messages.is_empty()).then_some(messages)
    }
}

impl ResolveVariable for CollectorResolver {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        if (variable as usize) < TOTAL_EVENT_COUNT {
            Variable::Integer(Collector::read_event_metric(variable as usize) as i64)
        } else if let Some(metric_type) =
            MetricType::from_code(variable as u64 - TOTAL_EVENT_COUNT as u64)
        {
            Variable::Float(Collector::read_metric(metric_type))
        } else {
            Variable::Integer(0)
        }
    }
}

impl AlertContent {
    pub fn build(&self) -> String {
        let mut buf = String::with_capacity(self.len());
        for token in &self.0 {
            token.write(&mut buf);
        }
        buf
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.iter().map(|t| t.len()).sum()
    }
}

impl AlertContentToken {
    fn write(&self, buf: &mut String) {
        match self {
            AlertContentToken::Text(text) => buf.push_str(text),
            AlertContentToken::Metric(metric_type) => {
                let _ = write!(buf, "{}", Collector::read_metric(*metric_type));
            }
            AlertContentToken::Event(event_type) => {
                let _ = write!(buf, "{}", Collector::read_event_metric(event_type.id()));
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            AlertContentToken::Text(s) => s.len(),
            AlertContentToken::Metric(_) | AlertContentToken::Event(_) => 10,
        }
    }
}
