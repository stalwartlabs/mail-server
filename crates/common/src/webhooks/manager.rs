/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{SharedCore, IPC_CHANNEL_BUFFER};
use ahash::AHashMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ring::hmac;
use tokio::sync::mpsc;
use utils::snowflake::SnowflakeIdGenerator;

use super::{Webhook, WebhookEvents, WebhookPayload, WebhookType};

pub enum WebhookEvent {
    Send {
        typ: WebhookType,
        payload: Arc<WebhookPayload>,
    },
    Success {
        webhook_id: u64,
    },
    Retry {
        webhook_id: u64,
        events: WebhookEvents,
    },
    Stop,
}

pub const LONG_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

struct PendingEvents {
    next_delivery: Instant,
    pending_events: WebhookEvents,
    retry_num: u32,
    in_flight: bool,
}

pub fn spawn_webhook_manager(core: SharedCore) -> mpsc::Sender<WebhookEvent> {
    let (webhook_tx, mut webhook_rx) = mpsc::channel(IPC_CHANNEL_BUFFER);

    let webhook_tx_ = webhook_tx.clone();

    tokio::spawn(async move {
        let mut wakeup_time = LONG_SLUMBER;
        let mut pending_events: AHashMap<u64, PendingEvents> = AHashMap::new();
        let id_generator = SnowflakeIdGenerator::new();

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(wakeup_time, webhook_rx.recv()).await;

            // Load settings
            let core = core.load_full();

            match event_or_timeout {
                Ok(Some(event)) => match event {
                    WebhookEvent::Send { typ, payload } => {
                        for (webhook_id, webhook) in &core.web_hooks.hooks {
                            if webhook.events.contains(&typ) {
                                pending_events.entry(*webhook_id).or_default().push(
                                    super::WebhookEvent {
                                        id: id_generator.generate().unwrap_or_default(),
                                        created_at: Utc::now(),
                                        typ,
                                        data: payload.clone(),
                                    },
                                );
                            }
                        }
                    }
                    WebhookEvent::Success { webhook_id } => {
                        if let Some(pending_events) = pending_events.get_mut(&webhook_id) {
                            pending_events.success();
                        }
                    }
                    WebhookEvent::Retry { webhook_id, events } => {
                        pending_events.entry(webhook_id).or_default().retry(events);
                    }
                    WebhookEvent::Stop => break,
                },
                Ok(None) => {
                    break;
                }
                Err(_) => (),
            }

            // Process events
            let mut delete_ids = Vec::new();
            let mut next_retry = None;
            for (webhook_id, events) in &mut pending_events {
                if let Some(webhook) = core.web_hooks.hooks.get(webhook_id) {
                    if events.next_delivery <= Instant::now() {
                        if !events.is_empty() {
                            events.next_delivery = Instant::now() + webhook.throttle;
                            if !events.in_flight {
                                events.in_flight = true;
                                spawn_webhook_handler(
                                    webhook.clone(),
                                    events.take_events(),
                                    webhook_tx.clone(),
                                );
                            }
                        } else {
                            // No more events for webhook
                            delete_ids.push(*webhook_id);
                        }
                    } else if !events.is_empty() {
                        // Retry later
                        let this_retry = events.next_delivery - Instant::now();
                        match next_retry {
                            Some(next_retry) if this_retry >= next_retry => {}
                            _ => {
                                next_retry = Some(this_retry);
                            }
                        }
                    }
                } else {
                    delete_ids.push(*webhook_id);
                }
            }
            wakeup_time = next_retry.unwrap_or(LONG_SLUMBER);

            // Delete removed or empty webhooks
            for webhook_id in delete_ids {
                pending_events.remove(&webhook_id);
            }
        }
    });

    webhook_tx_
}

fn spawn_webhook_handler(
    webhook: Arc<Webhook>,
    events: WebhookEvents,
    webhook_tx: mpsc::Sender<WebhookEvent>,
) {
    tokio::spawn(async move {
        let response = match post_webhook_events(&webhook, &events).await {
            Ok(_) => WebhookEvent::Success {
                webhook_id: webhook.id,
            },
            Err(err) => {
                tracing::warn!("Failed to post webhook events: {}", err);
                WebhookEvent::Retry {
                    webhook_id: webhook.id,
                    events,
                }
            }
        };

        // Notify manager
        if let Err(err) = webhook_tx.send(response).await {
            tracing::error!("Failed to send webhook event: {}", err);
        }
    });
}

async fn post_webhook_events(webhook: &Webhook, events: &WebhookEvents) -> Result<(), String> {
    // Serialize body
    let body = serde_json::to_string(events)
        .map_err(|err| format!("Failed to serialize events: {}", err))?;

    // Add HMAC-SHA256 signature
    let mut headers = webhook.headers.clone();
    if !webhook.key.is_empty() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, webhook.key.as_bytes());
        let tag = hmac::sign(&key, body.as_bytes());

        headers.insert(
            "X-Signature",
            STANDARD.encode(tag.as_ref()).parse().unwrap(),
        );
    }

    // Send request
    let response = reqwest::Client::builder()
        .timeout(webhook.timeout)
        .danger_accept_invalid_certs(webhook.tls_allow_invalid_certs)
        .build()
        .map_err(|err| format!("Failed to create HTTP client: {}", err))?
        .post(&webhook.url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| format!("Webhook request to {} failed: {err}", webhook.url))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Webhook request to {} failed with code {}: {}",
            webhook.url,
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        ))
    }
}

impl Default for PendingEvents {
    fn default() -> Self {
        Self {
            next_delivery: Instant::now(),
            pending_events: WebhookEvents::default(),
            retry_num: 0,
            in_flight: false,
        }
    }
}

impl PendingEvents {
    pub fn push(&mut self, event: super::WebhookEvent) {
        self.pending_events.events.push(event);
    }

    pub fn success(&mut self) {
        self.in_flight = false;
        self.retry_num = 0;
    }

    pub fn retry(&mut self, events: WebhookEvents) {
        // Backoff
        self.next_delivery = Instant::now() + Duration::from_secs(2u64.pow(self.retry_num));
        self.retry_num += 1;
        self.in_flight = false;

        for event in events.events {
            // Drop failed events older than 5 minutes
            if event.created_at + Duration::from_secs(5 * 60) >= Utc::now() {
                self.pending_events.events.push(event);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending_events.events.is_empty()
    }

    pub fn take_events(&mut self) -> WebhookEvents {
        std::mem::take(&mut self.pending_events)
    }
}
